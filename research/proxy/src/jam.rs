use std::{fmt, io};

use bitstream_io::{BitRead, BitReader, LittleEndian};

pub mod schema;

pub enum Value {
    U1(bool),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    F32(f32),
    F64(f64),
    String(String),
    Struct(Vec<(String, Value)>),
    Object(Vec<u8>),
    Array(Vec<Value>),
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::U1(v) => v.fmt(f),
            Value::U8(v) => v.fmt(f),
            Value::U16(v) => v.fmt(f),
            Value::U32(v) => v.fmt(f),
            Value::U64(v) => v.fmt(f),
            Value::F32(v) => v.fmt(f),
            Value::F64(v) => v.fmt(f),
            Value::String(v) => v.fmt(f),
            Value::Struct(v) => {
                let mut s = f.debug_struct("");
                for (name, value) in v.iter() {
                    s.field(&name.to_string(), value);
                }
                s.finish()
            }
            Value::Object(v) => {
                write!(f, "0x")?;
                for b in v {
                    write!(f, "{b:02x}")?;
                }
                Ok(())
            }
            Value::Array(v) => v.fmt(f),
        }
    }
}

pub fn decode(message: &schema::Message, buf: &mut &[u8]) -> io::Result<Value> {
    let mut reader = BitReader::endian(buf, LittleEndian);
    Ok(Value::Struct(decode_fields(&message.fields, &mut reader)?))
}

fn decode_fields(
    fields: &[schema::Field],
    reader: &mut impl BitRead,
) -> io::Result<Vec<(String, Value)>> {
    fields
        .iter()
        .map(|f| Ok((f.name.clone(), decode_value(&f.r#type, f, reader)?)))
        .collect()
}

fn decode_value(ty: &str, field: &schema::Field, reader: &mut impl BitRead) -> io::Result<Value> {
    if !matches!(ty, "U1" | "Struct" | "Array") {
        reader.byte_align();
    }

    Ok(match ty {
        "U1" => Value::U1(reader.read_bit()?),
        "U8" => Value::U8(reader.read::<8, u8>()?),
        "U16" => Value::U16(reader.read::<16, u16>()?),
        "U32" => Value::U32(reader.read::<32, u32>()?),
        "U64" => Value::U64(reader.read::<64, u64>()?),
        "F32" => Value::F32(f32::from_bits(reader.read::<32, u32>()?)),
        "F64" => Value::F64(f64::from_bits(reader.read::<64, u64>()?)),
        "String" => {
            let mut bytes = Vec::new();
            loop {
                let byte = reader.read::<8, u8>()?;
                if byte == 0 {
                    break;
                }
                bytes.push(byte);
            }
            Value::String(String::from_utf8_lossy(&bytes).into_owned())
        }
        "Struct" => Value::Struct(decode_fields(&field.fields, reader)?),
        "Object" => {
            let n = reader.read::<32, u32>()? as usize;
            Value::Object(reader.read_to_vec(n)?)
        }
        "Array" => {
            let n = match field.size {
                0 => {
                    reader.byte_align();
                    reader.read::<32, u32>()? as usize
                }
                n => n as usize,
            };

            let ty = field
                .type_name
                .as_deref()
                .ok_or(io::ErrorKind::InvalidData)?;

            Value::Array(
                (0..n)
                    .map(|_| decode_value(ty, field, reader))
                    .collect::<io::Result<_>>()?,
            )
        }
        _ => return Err(io::ErrorKind::InvalidData.into()),
    })
}

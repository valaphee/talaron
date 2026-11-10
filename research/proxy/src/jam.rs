use std::ops::{Index, IndexMut};
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

impl Value {
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::U8(v) => *v,
            _ => panic!(),
        }
    }

    pub fn as_u8_mut(&mut self) -> &mut u8 {
        match self {
            Self::U8(v) => v,
            _ => panic!(),
        }
    }

    pub fn as_u16(&self) -> u16 {
        match self {
            Self::U16(v) => *v,
            _ => panic!(),
        }
    }

    pub fn as_u16_mut(&mut self) -> &mut u16 {
        match self {
            Self::U16(v) => v,
            _ => panic!(),
        }
    }

    pub fn as_u32(&self) -> u32 {
        match self {
            Self::U32(v) => *v,
            _ => panic!(),
        }
    }

    pub fn as_u32_mut(&mut self) -> &mut u32 {
        match self {
            Self::U32(v) => v,
            _ => panic!(),
        }
    }

    pub fn as_u64(&self) -> u64 {
        match self {
            Self::U64(v) => *v,
            _ => panic!(),
        }
    }

    pub fn as_u64_mut(&mut self) -> &mut u64 {
        match self {
            Self::U64(v) => v,
            _ => panic!(),
        }
    }

    pub fn as_f32(&self) -> f32 {
        match self {
            Self::F32(v) => *v,
            _ => panic!(),
        }
    }

    pub fn as_f32_mut(&mut self) -> &mut f32 {
        match self {
            Self::F32(v) => v,
            _ => panic!(),
        }
    }

    pub fn as_f64(&self) -> f64 {
        match self {
            Self::F64(v) => *v,
            _ => panic!(),
        }
    }

    pub fn as_f64_mut(&mut self) -> &mut f64 {
        match self {
            Self::F64(v) => v,
            _ => panic!(),
        }
    }

    pub fn as_string(&self) -> &String {
        match self {
            Self::String(v) => v,
            _ => panic!(),
        }
    }

    pub fn as_string_mut(&mut self) -> &mut String {
        match self {
            Self::String(v) => v,
            _ => panic!(),
        }
    }

    pub fn as_slice(&self) -> &[Value] {
        match self {
            Self::Array(v) => v.as_slice(),
            _ => panic!(),
        }
    }

    pub fn as_mut_slice(&mut self) -> &mut [Value] {
        match self {
            Self::Array(v) => v.as_mut_slice(),
            _ => panic!(),
        }
    }
}

impl Index<&str> for Value {
    type Output = Value;

    fn index(&self, name: &str) -> &Self::Output {
        match self {
            Self::Struct(v) => &v.iter().find(|f| f.0 == name).unwrap().1,
            _ => panic!(),
        }
    }
}

impl IndexMut<&str> for Value {
    fn index_mut(&mut self, name: &str) -> &mut Self::Output {
        match self {
            Self::Struct(v) => &mut v.iter_mut().find(|f| f.0 == name).unwrap().1,
            _ => panic!(),
        }
    }
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

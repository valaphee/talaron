use std::{fmt, io};

use bytes::Buf as _;

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
    Struct(Vec<Value>),
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
                for (name, value) in v.iter().enumerate() {
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
    Ok(Value::Struct(decode_fields(&message.fields, buf)?))
}

fn decode_fields(fields: &[schema::Field], buf: &mut &[u8]) -> io::Result<Vec<Value>> {
    let mut bits = (0, 0);

    fields
        .iter()
        .map(|field| decode_value(&field.r#type, field, buf, &mut bits))
        .collect()
}

fn decode_value(
    ty: &str,
    field: &schema::Field,
    buf: &mut &[u8],
    bits: &mut (u8, u8),
) -> io::Result<Value> {
    if ty != "U1" {
        bits.1 = 0;
    }

    Ok(match ty {
        "U1" => {
            if bits.1 == 0 {
                *bits = (
                    buf.try_get_u8().map_err(|_| io::ErrorKind::UnexpectedEof)?,
                    8,
                );
            }

            let value = Value::U1(bits.0 & 1 != 0);
            bits.0 >>= 1;
            bits.1 -= 1;
            value
        }
        "U8" => Value::U8(buf.try_get_u8().map_err(|_| io::ErrorKind::UnexpectedEof)?),
        "U16" => Value::U16(
            buf.try_get_u16_le()
                .map_err(|_| io::ErrorKind::UnexpectedEof)?,
        ),
        "U32" => Value::U32(
            buf.try_get_u32_le()
                .map_err(|_| io::ErrorKind::UnexpectedEof)?,
        ),
        "U64" => Value::U64(
            buf.try_get_u64_le()
                .map_err(|_| io::ErrorKind::UnexpectedEof)?,
        ),
        "F32" => Value::F32(
            buf.try_get_f32_le()
                .map_err(|_| io::ErrorKind::UnexpectedEof)?,
        ),
        "F64" => Value::F64(
            buf.try_get_f64_le()
                .map_err(|_| io::ErrorKind::UnexpectedEof)?,
        ),
        "String" => {
            let n = buf
                .iter()
                .position(|&b| b == 0)
                .ok_or(io::ErrorKind::UnexpectedEof)?;
            let value = String::from_utf8_lossy(&buf[..n]).into_owned();
            buf.advance(n + 1);
            Value::String(value)
        }
        "Struct" => Value::Struct(decode_fields(&field.fields, buf)?),
        "Object" => {
            let n = buf
                .try_get_u32_le()
                .map_err(|_| io::ErrorKind::UnexpectedEof)? as usize;
            let value = buf[..n].to_vec();
            buf.advance(n);
            Value::Object(value)
        }
        "Array" => {
            let n = buf
                .try_get_u32_le()
                .map_err(|_| io::ErrorKind::UnexpectedEof)? as usize;
            let mut bits = (0, 0);

            Value::Array(
                (0..n)
                    .map(|_| {
                        decode_value(field.type_name.as_deref().unwrap(), field, buf, &mut bits)
                    })
                    .collect::<io::Result<_>>()?,
            )
        }
        _ => return Err(io::ErrorKind::InvalidData.into()),
    })
}

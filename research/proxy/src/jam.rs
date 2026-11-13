use std::ops::{Index, IndexMut};
use std::{fmt, io};

use bitstream_io::{BitRead, BitReader, BitWrite, BitWriter, LittleEndian};

use crate::FIELD;

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
    ArrayFixed(Vec<Value>),
}

impl Value {
    pub fn as_u1(&self) -> bool {
        let Self::U1(value) = self else {
            panic!();
        };
        *value
    }

    pub fn as_u1_mut(&mut self) -> &mut bool {
        let Self::U1(value) = self else {
            panic!();
        };
        value
    }

    pub fn as_u8(&self) -> u8 {
        let Self::U8(value) = self else {
            panic!();
        };
        *value
    }

    pub fn as_u8_mut(&mut self) -> &mut u8 {
        let Self::U8(value) = self else {
            panic!();
        };
        value
    }

    pub fn as_u16(&self) -> u16 {
        let Self::U16(value) = self else {
            panic!();
        };
        *value
    }

    pub fn as_u16_mut(&mut self) -> &mut u16 {
        let Self::U16(value) = self else {
            panic!();
        };
        value
    }

    pub fn as_u32(&self) -> u32 {
        let Self::U32(value) = self else {
            panic!();
        };
        *value
    }

    pub fn as_u32_mut(&mut self) -> &mut u32 {
        let Self::U32(value) = self else {
            panic!();
        };
        value
    }

    pub fn as_u64(&self) -> u64 {
        let Self::U64(value) = self else {
            panic!();
        };
        *value
    }

    pub fn as_u64_mut(&mut self) -> &mut u64 {
        let Self::U64(value) = self else {
            panic!();
        };
        value
    }

    pub fn as_f32(&self) -> f32 {
        let Self::F32(value) = self else {
            panic!();
        };
        *value
    }

    pub fn as_f32_mut(&mut self) -> &mut f32 {
        let Self::F32(value) = self else {
            panic!();
        };
        value
    }

    pub fn as_f64(&self) -> f64 {
        let Self::F64(value) = self else {
            panic!();
        };
        *value
    }

    pub fn as_f64_mut(&mut self) -> &mut f64 {
        let Self::F64(value) = self else {
            panic!();
        };
        value
    }

    pub fn as_string(&self) -> &String {
        let Self::String(value) = self else {
            panic!();
        };
        value
    }

    pub fn as_string_mut(&mut self) -> &mut String {
        let Self::String(value) = self else {
            panic!();
        };
        value
    }

    pub fn as_array(&self) -> &[Value] {
        let (Self::Array(values) | Self::ArrayFixed(values)) = self else {
            panic!();
        };
        values
    }

    pub fn as_array_mut(&mut self) -> &mut [Value] {
        let (Self::Array(values) | Self::ArrayFixed(values)) = self else {
            panic!();
        };
        values
    }
}

impl Index<&str> for Value {
    type Output = Value;

    fn index(&self, name: &str) -> &Self::Output {
        let Self::Struct(fields) = self else {
            panic!();
        };

        &fields
            .iter()
            .find(|(field_name, _)| field_name == name)
            .unwrap()
            .1
    }
}

impl IndexMut<&str> for Value {
    fn index_mut(&mut self, name: &str) -> &mut Self::Output {
        let Self::Struct(fields) = self else {
            panic!();
        };

        &mut fields
            .iter_mut()
            .find(|(field_name, _)| field_name == name)
            .unwrap()
            .1
    }
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::U1(value) => value.fmt(f),
            Self::U8(value) => value.fmt(f),
            Self::U16(value) => value.fmt(f),
            Self::U32(value) => value.fmt(f),
            Self::U64(value) => value.fmt(f),
            Self::F32(value) => value.fmt(f),
            Self::F64(value) => value.fmt(f),
            Self::String(value) => value.fmt(f),
            Self::Struct(fields) => {
                let mut debug = f.debug_struct("");
                for (name, value) in fields {
                    debug.field(&format!("{FIELD}{name}{FIELD:#}"), value);
                }
                debug.finish()
            }
            Self::Object(bytes) => {
                write!(f, "0x")?;
                for byte in bytes {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
            Self::Array(values) | Self::ArrayFixed(values) => values.fmt(f),
        }
    }
}

pub fn encode(value: &Value, buf: &mut impl io::Write) -> io::Result<()> {
    let mut writer = BitWriter::endian(buf, LittleEndian);
    value.encode(&mut writer)?;
    writer.byte_align()
}

impl Value {
    fn encode(&self, writer: &mut impl BitWrite) -> io::Result<()> {
        if !matches!(self, Self::U1(_) | Self::Struct(_) | Self::ArrayFixed(_)) {
            writer.byte_align()?;
        }

        match self {
            Self::U1(value) => writer.write_bit(*value),
            Self::U8(value) => writer.write_from(*value),
            Self::U16(value) => writer.write_from(*value),
            Self::U32(value) => writer.write_from(*value),
            Self::U64(value) => writer.write_from(*value),
            Self::F32(value) => writer.write_from(*value),
            Self::F64(value) => writer.write_from(*value),
            Self::String(value) => {
                if value.as_bytes().contains(&0) {
                    return Err(io::ErrorKind::InvalidInput.into());
                }

                writer.write_bytes(value.as_bytes())?;
                writer.write_from(0u8)
            }
            Self::Struct(fields) => fields
                .iter()
                .try_for_each(|(_, value)| value.encode(writer)),
            Self::Object(bytes) => {
                writer.write_from(
                    u32::try_from(bytes.len()).map_err(|_| io::ErrorKind::InvalidInput)?,
                )?;
                writer.write_bytes(bytes)
            }
            Self::Array(values) | Self::ArrayFixed(values) => {
                if matches!(self, Self::Array(_)) {
                    writer.write_from(
                        u32::try_from(values.len()).map_err(|_| io::ErrorKind::InvalidInput)?,
                    )?;
                }

                values.iter().try_for_each(|value| value.encode(writer))
            }
        }
    }
}

pub fn decode(message: &schema::Message, buf: &mut &[u8]) -> io::Result<Value> {
    let mut reader = BitReader::endian(buf, LittleEndian);
    decode_fields(&message.fields, &mut reader).map(Value::Struct)
}

fn decode_fields(
    fields: &[schema::Field],
    reader: &mut impl BitRead,
) -> io::Result<Vec<(String, Value)>> {
    fields
        .iter()
        .map(|field| {
            let value = decode_value(&field.r#type, field, reader)?;
            Ok((field.name.clone(), value))
        })
        .collect()
}

fn decode_value(
    type_name: &str,
    field: &schema::Field,
    reader: &mut impl BitRead,
) -> io::Result<Value> {
    if !matches!(type_name, "U1" | "Struct" | "Array") {
        reader.byte_align();
    }

    Ok(match type_name {
        "U1" => Value::U1(reader.read_bit()?),
        "U8" => Value::U8(reader.read_to()?),
        "U16" => Value::U16(reader.read_to()?),
        "U32" => Value::U32(reader.read_to()?),
        "U64" => Value::U64(reader.read_to()?),
        "F32" => Value::F32(reader.read_to()?),
        "F64" => Value::F64(reader.read_to()?),
        "String" => {
            let mut bytes = Vec::new();
            loop {
                match reader.read_to::<u8>()? {
                    0 => break,
                    byte => bytes.push(byte),
                }
            }
            Value::String(String::from_utf8_lossy(&bytes).into_owned())
        }
        "Struct" => Value::Struct(decode_fields(&field.fields, reader)?),
        "Object" => {
            let length = reader.read_to::<u32>()? as usize;
            Value::Object(reader.read_to_vec(length)?)
        }
        "Array" => {
            let length = match field.size {
                0 => {
                    reader.byte_align();
                    reader.read_to::<u32>()? as usize
                }
                length => length as usize,
            };
            let type_name = field
                .type_name
                .as_deref()
                .ok_or(io::ErrorKind::InvalidData)?;
            let values = (0..length)
                .map(|_| decode_value(type_name, field, reader))
                .collect::<io::Result<Vec<_>>>()?;

            if field.size == 0 {
                Value::Array(values)
            } else {
                Value::ArrayFixed(values)
            }
        }
        _ => return Err(io::ErrorKind::InvalidData.into()),
    })
}

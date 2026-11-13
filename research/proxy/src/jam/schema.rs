use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};

pub struct Protocol {
    pub name:     String,
    pub crc:      u32,
    pub messages: Vec<Message>,
}

pub struct Message {
    pub id:     u32,
    pub name:   String,
    pub fields: Vec<Field>,
}

pub struct Field {
    pub name:      String,
    pub r#type:    String,
    pub size:      usize,
    pub type_name: Option<String>,
    pub fields:    Vec<Field>,
}

pub fn parse(xml: &str) -> Vec<Protocol> {
    let mut reader = Reader::from_str(xml);
    let config = reader.config_mut();
    config.trim_text(true);
    config.expand_empty_elements = true;

    let mut protocols = Vec::new();

    loop {
        match reader.read_event().unwrap() {
            Event::Start(element) if element.name().into_inner() == "Protocol" => {
                protocols.push(parse_protocol(&mut reader, &element));
            }
            Event::Eof => break,
            _ => {}
        }
    }

    protocols
}

fn parse_protocol(reader: &mut Reader<&[u8]>, element: &BytesStart<'_>) -> Protocol {
    let mut protocol = Protocol {
        name:     attr(element, "Name").unwrap(),
        crc:      u32::from_str_radix(attr(element, "Crc").unwrap().trim_start_matches("0x"), 16)
            .unwrap(),
        messages: Vec::new(),
    };

    loop {
        match reader.read_event().unwrap() {
            Event::Start(element) if element.name().into_inner() == "Message" => {
                protocol.messages.push(Message {
                    id:     attr(&element, "Id").unwrap().parse().unwrap(),
                    name:   attr(&element, "Name").unwrap(),
                    fields: parse_fields(reader, "Message"),
                });
            }
            Event::End(element) if element.name().into_inner() == "Protocol" => break,
            Event::Eof => break,
            _ => {}
        }
    }

    protocol
}

fn parse_fields(reader: &mut Reader<&[u8]>, end: &str) -> Vec<Field> {
    let mut fields = Vec::new();

    loop {
        match reader.read_event().unwrap() {
            Event::Start(element) => {
                let type_name = element.name().into_inner();

                fields.push(Field {
                    name:      attr(&element, "Name").unwrap(),
                    r#type:    type_name.to_owned(),
                    size:      attr(&element, "Size").map_or(0, |size| size.parse().unwrap()),
                    type_name: attr(&element, "TypeName"),
                    fields:    parse_fields(reader, type_name),
                });
            }
            Event::End(element) if element.name().into_inner() == end => break,
            Event::Eof => break,
            _ => {}
        }
    }

    fields
}

fn attr(element: &BytesStart<'_>, name: &str) -> Option<String> {
    element.try_get_attribute(name).unwrap().map(|attribute| {
        attribute
            .normalized_value(XmlVersion::Implicit1_0)
            .unwrap()
            .into_owned()
    })
}

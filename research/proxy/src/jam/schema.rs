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
    let mut xml = Reader::from_str(xml);
    xml.config_mut().trim_text(true);
    xml.config_mut().expand_empty_elements = true;

    let mut protocols = Vec::new();

    loop {
        match xml.read_event().unwrap() {
            Event::Start(e) if e.name().0 == "Protocol" => {
                protocols.push(parse_protocol(&mut xml, &e));
            }
            Event::Eof => break,
            _ => {}
        }
    }

    protocols
}

fn parse_protocol(xml: &mut Reader<&[u8]>, e: &BytesStart<'_>) -> Protocol {
    let mut protocol = Protocol {
        name:     attr(e, "Name").unwrap(),
        crc:      u32::from_str_radix(attr(e, "Crc").unwrap().trim_start_matches("0x"), 16)
            .unwrap(),
        messages: Vec::new(),
    };

    loop {
        match xml.read_event().unwrap() {
            Event::Start(e) if e.name().0 == "Message" => {
                protocol.messages.push(Message {
                    id:     attr(&e, "Id").unwrap().parse().unwrap(),
                    name:   attr(&e, "Name").unwrap(),
                    fields: parse_fields(xml, "Message"),
                });
            }
            Event::End(e) if e.name().0 == "Protocol" => break,
            Event::Eof => break,
            _ => {}
        }
    }

    protocol
}

fn parse_fields(xml: &mut Reader<&[u8]>, end: &str) -> Vec<Field> {
    let mut fields = Vec::new();

    loop {
        match xml.read_event().unwrap() {
            Event::Start(e) => {
                fields.push(Field {
                    name:      attr(&e, "Name").unwrap(),
                    r#type:    e.name().0.to_owned(),
                    size:      attr(&e, "Size").map_or(0, |v| v.parse().unwrap()),
                    type_name: attr(&e, "TypeName"),
                    fields:    parse_fields(xml, e.name().0),
                });
            }
            Event::End(e) if e.name().0 == end => break,
            Event::Eof => break,
            _ => {}
        }
    }

    fields
}

fn attr(e: &BytesStart<'_>, name: &str) -> Option<String> {
    e.try_get_attribute(name).unwrap().map(|a| {
        a.normalized_value(XmlVersion::Implicit1_0)
            .unwrap()
            .into_owned()
    })
}

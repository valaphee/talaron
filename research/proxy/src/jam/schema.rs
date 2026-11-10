use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};

pub struct Protocol {
    pub messages: Vec<Message>,
}

pub struct Message {
    pub id:     u32,
    pub fields: Vec<Field>,
}

pub struct Field {
    pub r#type:    String,
    pub type_name: Option<String>,
    pub fields:    Vec<Field>,
}

pub fn parse(xml: &str) -> Vec<Protocol> {
    let mut xml = Reader::from_str(xml);
    xml.config_mut().trim_text(true);

    let mut protocols = Vec::new();

    loop {
        match xml.read_event().unwrap() {
            Event::Start(e) if e.name().as_ref() == "Protocol" => {
                protocols.push(parse_protocol(&mut xml));
            }
            Event::Eof => break,
            _ => {}
        }
    }

    protocols
}

fn parse_protocol(xml: &mut Reader<&[u8]>) -> Protocol {
    let mut protocol = Protocol {
        messages: Vec::new(),
    };

    loop {
        match xml.read_event().unwrap() {
            Event::Empty(e) if e.name().0 == "Message" => {
                protocol.messages.push(Message {
                    id:     attr(&e, "Id").unwrap().parse().unwrap(),
                    fields: Vec::new(),
                });
            }
            Event::Start(e) if e.name().0 == "Message" => {
                protocol.messages.push(Message {
                    id:     attr(&e, "Id").unwrap().parse().unwrap(),
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
            Event::Empty(e) => fields.push(parse_field(&e, Vec::new())),
            Event::Start(e) => fields.push(parse_field(&e, parse_fields(xml, e.name().as_ref()))),
            Event::End(e) if e.name().as_ref() == end => break,
            Event::Eof => break,
            _ => {}
        }
    }

    fields
}

fn parse_field(e: &BytesStart<'_>, fields: Vec<Field>) -> Field {
    Field {
        r#type: e.name().as_ref().to_owned(),
        type_name: attr(e, "TypeName"),
        fields,
    }
}

fn attr(e: &BytesStart<'_>, name: &str) -> Option<String> {
    e.try_get_attribute(name)
        .unwrap()
        .map(|a| a.value.into_owned())
}

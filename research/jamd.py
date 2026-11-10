import struct
import sys
import xml.etree.ElementTree as ET

import pefile

TYPES = (
    "U1",
    "U8",
    "U8",
    "U8",
    "U16",
    "U16",
    "U32",
    "U32",
    "U64",
    "U64",
    "F32",
    "F64",
    "String",
    "String",
    "Struct",
    "Object",
    "Dynamic",
)

data = open(sys.argv[1], "rb").read()

pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase


def offset(address, length=1):
    rva = address - base
    if rva < 0:
        return None

    section = pe.get_section_by_rva(rva)
    if section is None or rva - section.VirtualAddress + length > section.SizeOfRawData:
        return None

    pos = section.PointerToRawData + rva - section.VirtualAddress
    return pos if pos + length <= len(data) else None


def cstring(address):
    if (pos := offset(address)) is None:
        return None

    end = data.find(b"\0", pos)
    if end < 0:
        return None

    try:
        return data[pos:end].decode("ascii")
    except UnicodeDecodeError:
        return None


def add_struct(parent, address):
    while (pos := offset(address, 0x30)) is not None:
        name, type, size, nested = struct.unpack_from("<QI8xiQ", data, pos)
        if type == 17:
            return True
        if type > 17:
            return False

        elem = ET.SubElement(
            parent,
            "Array" if size != 0 else TYPES[type],
            Name=cstring(name) or str(len(parent)),
        )

        if size != 0:
            if size != -1:
                elem.set("Size", str(size))

            elem.set("TypeName", TYPES[type])

        if type == 14 and not add_struct(elem, nested):
            return False

        address += 0x30

    return False


root = ET.Element("Protocols")
protocols = {}

section = next(
    section for section in pe.sections if section.Name.rstrip(b"\0") == b".data"
)

for pos in range(
    section.PointerToRawData,
    min(section.PointerToRawData + section.SizeOfRawData, len(data)) - 0x20 + 1,
    0x10,
):
    message_name, protocol_name, fields, protocol_crc, message_id = struct.unpack_from(
        "<QQQII", data, pos
    )

    elem = ET.Element(
        "Message", Id=str(message_id), Name=cstring(message_name) or str(message_id)
    )
    if not add_struct(elem, fields):
        continue

    if protocol_crc not in protocols:
        protocols[protocol_crc] = ET.SubElement(
            root,
            "Protocol",
            Name=cstring(protocol_name) or f"0x{protocol_crc:08X}",
            Crc=f"0x{protocol_crc:08X}",
        )

    protocols[protocol_crc].append(elem)

for protocol in root:
    protocol[:] = sorted(protocol, key=lambda message: int(message.attrib["Id"]))

root[:] = sorted(
    root,
    key=lambda protocol: int(protocol[0].attrib["Id"]),
)

ET.indent(root, space="  ")

ET.ElementTree(root).write(
    sys.argv[2] if len(sys.argv) > 2 else "jam.xml",
    encoding="utf-8",
    xml_declaration=True,
)

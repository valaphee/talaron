import struct
import sys
import xml.etree.ElementTree as ET

import pefile

CRCS = {
    0x05BE342F,
    0x075AFBC5,
    0x0A6E6ECC,
    0x0DFEEFEF,
    0x14C5E059,
    0x16312E56,
    0x181CF937,
    0x198CA63B,
    0x1A264832,
    0x1A9C127C,
    0x1AEC41AE,
    0x1B564277,
    0x1BCB37DC,
    0x1D00E9DA,
    0x1D80BD86,
    0x1E46B3AA,
    0x1EA3BF43,
    0x22216E16,
    0x22CA1BFD,
    0x25490475,
    0x267FDE9E,
    0x281F3E3D,
    0x291811E5,
    0x2C854E29,
    0x2C8C994D,
    0x2E6B8C56,
    0x2F1DA043,
    0x308BC8B1,
    0x345AF177,
    0x34BB385D,
    0x3B1D1168,
    0x3B5D9E99,
    0x3E43C20F,
    0x4116E22C,
    0x433CA810,
    0x46DC9706,
    0x47688EC4,
    0x48941D74,
    0x49963FA6,
    0x4C5A1F25,
    0x50BA8C3B,
    0x5635CB1C,
    0x58E10251,
    0x5953BDFD,
    0x5CD15738,
    0x5E561ADC,
    0x5F8C3ADD,
    0x63FA6DC3,
    0x68F2D5FE,
    0x692C511B,
    0x6D31E691,
    0x6F620C03,
    0x6F7DF2DF,
    0x70E37EFB,
    0x737CF172,
    0x7398092F,
    0x7449DECE,
    0x747E5A91,
    0x76CAD415,
    0x78D38432,
    0x80937E5C,
    0x80A03C14,
    0x81BB0A13,
    0x82A5DEA2,
    0x8578DB35,
    0x88925A87,
    0x8903C12A,
    0x8A56717E,
    0x8AC415DE,
    0x8B3DC153,
    0x8C7A7B4E,
    0x8E672E98,
    0x8FCC15DA,
    0x9781E741,
    0x981D6A52,
    0x99CE7F01,
    0xA2B43EC7,
    0xA3019ADB,
    0xA5960CBD,
    0xA7EDA1ED,
    0xABD20F26,
    0xAD1C34BA,
    0xAFBE5037,
    0xAFCDB711,
    0xB15E0A6C,
    0xB5116ECD,
    0xB7BCE830,
    0xBCD57A46,
    0xBDE7B927,
    0xC1768FCA,
    0xC1DD27A7,
    0xC29802A1,
    0xC59CD2FD,
    0xC6114F82,
    0xC64B397E,
    0xC9686B0D,
    0xD077DE5C,
    0xD1996263,
    0xD46B651B,
    0xD4B86992,
    0xD69E9940,
    0xDDA583EF,
    0xE498CA04,
    0xE4DB79D6,
    0xE5FF9BD4,
    0xE60AB657,
    0xE8B8D379,
    0xEA4420DD,
    0xEB45AD29,
    0xEE534BD1,
    0xF0EE0EF0,
    0xF6F4E6A5,
    0xFD75052A,
    0xFDEC4D9E,
}

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
        name, type, size, nested = struct.unpack_from("<QI8xIQ", data, pos)

        if type == 17:
            return True

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
protocols = {
    crc: ET.SubElement(root, "Protocol", Name=str(index + 1), Crc=f"0x{crc:08X}")
    for index, crc in enumerate(sorted(CRCS))
}

section = next(
    section for section in pe.sections if section.Name.rstrip(b"\0") == b".data"
)

for pos in range(
    section.PointerToRawData,
    min(section.PointerToRawData + section.SizeOfRawData, len(data)) - 0x20 + 1,
    8,
):
    fields, crc, id = struct.unpack_from("<16xQII", data, pos)
    if crc not in CRCS or not fields:
        continue

    protocol = protocols[crc]
    elem = ET.SubElement(protocol, "Message", Id=str(id), Name=str(id))
    if not add_struct(elem, fields):
        protocol.remove(elem)

for protocol in root:
    protocol[:] = sorted(protocol, key=lambda message: int(message.attrib["Id"]))

ET.indent(root, space="  ")

ET.ElementTree(root).write(
    sys.argv[2] if len(sys.argv) > 2 else "jam.xml",
    encoding="utf-8",
    xml_declaration=True,
)

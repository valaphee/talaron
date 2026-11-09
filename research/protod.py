import importlib
import io
import re
import sys
from pathlib import Path

from google.protobuf import (
    descriptor_pb2 as pb,
)
from google.protobuf import (
    descriptor_pool,
    message_factory,
    text_encoding,
    text_format,
)
from google.protobuf.message import DecodeError

TYPES = {
    value: name.removeprefix("TYPE_").lower()
    for name, value in pb.FieldDescriptorProto.Type.items()
}

LABELS = {
    1: "optional ",
    2: "required ",
    3: "repeated ",
}


def varint(pos):
    value = 0

    for shift in range(0, 70, 7):
        byte = data[pos]
        pos += 1

        if shift == 63 and byte > 1:
            break

        value |= (byte & 127) << shift

        if byte < 128:
            return value, pos

    raise ValueError


data = Path(sys.argv[1]).read_bytes()
root = Path(sys.argv[2] if len(sys.argv) == 3 else "proto").resolve()

files = {}

for match in re.finditer(b"\x0a", data):
    begin = match.start()

    try:
        length, pos = varint(begin + 1)

        if not 6 <= length <= 4096:
            continue

        if not data[pos : pos + length].endswith(b".proto"):
            continue
    except (ValueError, IndexError):
        continue

    pos = begin
    ends = []
    limit = min(len(data), begin + 16 * 1024 * 1024)

    while pos < limit:
        try:
            tag, end = varint(pos)
            number, wire = tag >> 3, tag & 7

            if not number or (number == 1 and pos != begin):
                break

            if wire not in (0, 2):
                break

            value, end = varint(end)

            if wire == 2:
                end += value

            if end > limit:
                break
        except (ValueError, IndexError):
            break

        ends.append(end)
        pos = end

    for end in reversed(ends):
        try:
            file = pb.FileDescriptorProto.FromString(data[begin:end])
        except DecodeError:
            continue

        if any(
            index < 0 or index >= len(file.dependency)
            for index in (*file.public_dependency, *file.weak_dependency)
        ):
            continue

        files.setdefault(file.name, file)
        break

root.mkdir(parents=True, exist_ok=True)

(root / "descriptors.pb").write_bytes(
    pb.FileDescriptorSet(file=files.values()).SerializeToString()
)

pool = descriptor_pool.DescriptorPool()
pool.AddSerializedFile(pb.DESCRIPTOR.serialized_pb)

for module in [
    "any",
    "api",
    "duration",
    "empty",
    "field_mask",
    "source_context",
    "struct",
    "timestamp",
    "type",
    "wrappers",
]:
    importlib.import_module(f"google.protobuf.{module}_pb2")


def resolve(name):
    try:
        pool.FindFileByName(name)
        return
    except KeyError:
        pass

    descriptor = files.get(name)

    if descriptor is None:
        builtin = descriptor_pool.Default().FindFileByName(name)
        descriptor = pb.FileDescriptorProto.FromString(builtin.serialized_pb)

    for dependency in descriptor.dependency:
        resolve(dependency)

    pool.AddSerializedFile(descriptor.SerializeToString())


for name in files:
    try:
        resolve(name)
    except (KeyError, TypeError, ValueError):
        continue


def options(desc):
    original = desc.options
    cls = message_factory.GetMessageClass(
        pool.FindMessageTypeByName(original.DESCRIPTOR.full_name)
    )
    decoded = cls.FromString(original.SerializeToString())
    result = []

    for field, value in decoded.ListFields():
        if field.name == "uninterpreted_option":
            continue

        name = f"(.{field.full_name})" if field.is_extension else field.name

        for item in value if field.is_repeated else [value]:
            out = io.StringIO()

            text_format.PrintFieldValue(
                field,
                item,
                out,
                as_utf8=False,
                as_one_line=True,
            )

            result.append(f"{name} = {out.getvalue().strip()}")

    return result


for name, file in files.items():
    path = (root / name).resolve()

    lines = ['syntax = "proto2";']

    def line(text, level=0):
        lines.append("  " * level + text)

    def block(desc, name, level=0):
        line(name + " {", level)

        for option in options(desc):
            line(f"option {option};", level + 1)

    def suffix(desc):
        items = options(desc)
        return " [" + ", ".join(items) + "]" if items else ""

    def field(item, level, maps, oneof=False):
        label = "" if oneof else LABELS[item.label]
        name = item.type_name or TYPES[item.type]

        if item.type_name in maps:
            key, value = maps[item.type_name].field
            name = f"map<{TYPES[key.type]}, {value.type_name or TYPES[value.type]}>"
            label = ""

        line(
            f"{label}{name} {item.name} = {item.number}{suffix(item)};",
            level,
        )

    def declarations(messages, enums, extensions, scope="", level=0):
        for item in extensions:
            line(f"extend {item.extendee} {{", level)
            field(item, level + 1, {})
            line("}", level)

        for enum in enums:
            block(enum, f"enum {enum.name}", level)

            for value in enum.value:
                line(
                    f"{value.name} = {value.number}{suffix(value)};",
                    level + 1,
                )

            line("}", level)

        for message in messages:
            if message.options.map_entry:
                continue

            name = scope + "." + message.name
            maps = {
                name + "." + nested.name: nested
                for nested in message.nested_type
                if nested.options.map_entry
            }

            block(message, f"message {message.name}", level)

            declarations(
                message.nested_type,
                message.enum_type,
                message.extension,
                name,
                level + 1,
            )

            for item in message.extension_range:
                end = "max" if item.end == 2**29 else str(item.end - 1)
                bounds = (
                    str(item.start)
                    if item.end == item.start + 1
                    else f"{item.start} to {end}"
                )

                line(
                    f"extensions {bounds}{suffix(item)};",
                    level + 1,
                )

            for item in message.field:
                if not item.HasField("oneof_index") or item.proto3_optional:
                    field(item, level + 1, maps)

            synthetic = {
                item.oneof_index for item in message.field if item.proto3_optional
            }

            for index, oneof in enumerate(message.oneof_decl):
                if index in synthetic:
                    continue

                block(oneof, f"oneof {oneof.name}", level + 1)

                for item in message.field:
                    if item.HasField("oneof_index") and item.oneof_index == index:
                        field(item, level + 2, maps, oneof=True)

                line("}", level + 1)

            line("}", level)

    if file.package:
        line(f"package {file.package};")

    for index, dependency in enumerate(file.dependency):
        if index in file.public_dependency:
            modifier = "public "
        elif index in file.weak_dependency:
            modifier = "weak "
        else:
            modifier = ""

        escaped = text_encoding.CEscape(dependency, as_utf8=False)
        line(f'import {modifier}"{escaped}";')

    for option in options(file):
        line(f"option {option};")

    declarations(
        file.message_type,
        file.enum_type,
        file.extension,
        "." + file.package if file.package else "",
    )

    for service in file.service:
        block(service, f"service {service.name}")

        for method in service.method:
            request = ("stream " if method.client_streaming else "") + method.input_type
            response = (
                "stream " if method.server_streaming else ""
            ) + method.output_type

            block(
                method,
                f"rpc {method.name} ({request}) returns ({response})",
                1,
            )
            line("}", 1)

        line("}")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

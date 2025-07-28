import re
import sys
from collections import deque
from dataclasses import dataclass, field
from utils import find_git_root, read_file

def default_types_factory() -> list:
    return {"u8": None, "u16": None, "u32": None, "u64": None, "u128": None, "ulong": None, "int": None, "long": None, "char": None, "long unsigned int": None}

@dataclass
class Definition:
    type: str
    name: str
    value: str

@dataclass
class ParseContext:
    required_types: list[str] = field(default_factory=list)
    existing_types: dict[str, str] = field(default_factory=default_types_factory)

    definitions: list[Definition] = field(default_factory=list)

patterns = {
    "typedef": r'typedef\s+((?:\w+\s+)*\w+)\s+(\w+)\s*;',
    "union": r'(typedef)?\s+union\s*\{([^}]*)\}\s*\w+\s*;',
    "struct": r'struct\s+(\w+)\s*\{([^}]*)\}\s*(\w*)\s*;',
}

def extract_members(union_or_struct_body: str) -> list[str]:
    member_pattern = re.compile(
        r'(\w+(?:\s*\*)?)\s+\w+\s*;',
        re.DOTALL
    )
    member_matches = member_pattern.findall(union_or_struct_body)
    member_matches = [x.rstrip("*").rstrip() for x in member_matches]
    return member_matches


def extract_required_types(content: str) -> list[str]:  
    sc_param_union  = re.compile(patterns["union"]).search(content)
    return extract_members(sc_param_union.group(0))

def type_def_present(ctx: ParseContext, type_name: str) -> bool:
    return next((True for x in ctx.definitions if x.name == type_name), False)

def resolve_requirement(ctx: ParseContext, required_type: str, idx: int):
    if type_def_present(ctx, required_type):
        return
    if required_type in ctx.existing_types:
        ctx.definitions.insert(idx, ctx.existing_types[required_type])
    else:
        ctx.required_types.insert(idx, required_type)

def handle_typedef(ctx: ParseContext, value: re.Match):
    src_type = value.group(2)
    dst_type = value.group(3)
    current_def: Definition = Definition(type="typedef",
                                         name=dst_type,
                                         value=value.group(0))
    ctx.existing_types[dst_type] = current_def

    try:
        required_type_idx = ctx.required_types.index(dst_type)
    except ValueError:
        return 

    resolve_requirement(ctx, src_type, required_type_idx-1)
    # We have typedef, but source type is not defined yet,
    # Fetch it later
    if src_type not in ctx.existing_types:
        ctx.required_types.insert(required_type_idx - 1, src_type)

    # Add definition for target type
    ctx.definitions.insert(required_type_idx, current_def)


def handle_struct(ctx: ParseContext, value: re.Match):
    struct_name = value.group(7)
    current_def: Definition = Definition(type="typedef",
                                         name=struct_name,
                                         value=value.group(0))
    ctx.existing_types[struct_name] = current_def

    try:
        required_type_idx = ctx.required_types.index(struct_name)
    except ValueError:
        return 

    members = extract_members(value.group(0))
    for member in members:
        resolve_requirement(ctx, member, required_type_idx-1)

    ctx.definitions.insert(required_type_idx, current_def) 

def extract_vmlinux_definitions(content: str, required_types: set[str]) -> list[Definition]:
    ctx: ParseContext = ParseContext(required_types=required_types)
    joined_regex = '|'.join(f'(?P<{name}>{pattern})' for name, pattern in patterns.items())
    print(joined_regex)
    for match in re.finditer(joined_regex, content):
        for name, value in match.groupdict().items():
            if not value:
                continue
            # print(f"Found {name}: {value}")
            if name == "typedef":
                handle_typedef(ctx, match)
            elif name == "struct":
                handle_struct(ctx, match)

    return ctx.definitions

def dump_definitions(output_file: str, defs: list[Definition]):
    with open(output_file, "w+") as f:
        f.write("\n".join([x.value for x in defs]))

def main():
    if len(sys.argv) < 4:
        handlers_file = f"{find_git_root()}/kmod/handler_wrappers.h"
        vmlinux_file = f"{find_git_root()}/kmod/vmlinux.h"
        output_file = f"{find_git_root()}/kmod/vmlinux_stripped.h"
    else:
        handlers_file = sys.argv[1]
        vmlinux_file = sys.argv[2]
        output_file = sys.argv[3]

    handlers_content = read_file(handlers_file) 
    vmlinux_content = read_file(vmlinux_file)

    required_types = extract_required_types(handlers_content)    
    definitions = extract_vmlinux_definitions(vmlinux_content, required_types)

    dump_definitions(output_file, definitions)

if __name__ == "__main__":
    main()
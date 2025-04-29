import sys
import re
import os
from dataclasses import dataclass, asdict
from dacite import from_dict
from typing import Optional, List, Dict, Tuple, Set
import json
from utils import find_git_root

@dataclass
class SyscallArgument:
    name: str
    type: str
    is_ptr: bool = False

@dataclass
class SyscallDefinition:
    name: str
    signature_str: str
    arguments: List[SyscallArgument]
        

syscall_map: Dict[str, SyscallDefinition] = {}


def get_syscall_definitions(lines) -> List[SyscallDefinition]:
    definitions: List[SyscallDefinition] = []
    combined_lines = "\n".join(lines)

    # Regex pattern to match syscall definitions across multiple lines
    lookup = r"SYSCALL_DEFINE\d\((\w+)\s*,?\s*([^)]*?)\)"
    matches = re.finditer(lookup, combined_lines, re.DOTALL)


    for match in matches:
        signature = match.group(0)  # The entire matched line
        syscall_name = match.group(1)

        arg_strings = match.group(2).split(",")


        arg_types: List[str] = arg_strings[::2]
        arg_names: List[str] = arg_strings[1::2]
        args: List[SyscallArgument] = []

        for n, t in zip(arg_names, arg_types):
            name = n.replace("\t", "").replace("\n", "").strip()
            type = t.replace("\t", "").replace("\n", "").replace("const", "").replace("__user", "").replace("*", "").strip()
            is_ptr: bool = "*" in t

            args.append(SyscallArgument(
                name=name, type=type, is_ptr=is_ptr
            ))


        definitions.append(SyscallDefinition(name=syscall_name, signature_str=signature, arguments=args))

    return definitions


def get_buf_idxs(line: str) -> Tuple[int, int]:
    buffer_size_idx = -1
    buffer_idx = -1

    pattern = r"SYSCALL_DEFINE\d\((\w+)(?:\s*,\s*(.*?))?\)"
    match = re.search(pattern, line)

    if match is not None and len(match.groups()) >= 2:
        group = match.group(2)
        if group is None:
            return buffer_idx, buffer_size_idx

        params: list[str] = group.split(",")

        for idx, param in enumerate(params):
            if "char __user *" in param:
                buffer_idx = idx
                break

        # check if the next parameter is of type size_t
        if buffer_idx != -1 and buffer_idx + 2 < len(params):
            next_param_type = params[buffer_idx + 2].strip()
            if "size_t" in next_param_type:
                buffer_size_idx = buffer_idx + 1  # Adjusting for the index

    return buffer_idx, buffer_size_idx

def load_defs_from_cache() -> Optional[dict]:
    cache_file_path = os.path.expanduser("~/.cache/rsyscaller/syscall_definitions")
    if os.path.exists(cache_file_path):
        with open(cache_file_path, "r") as f:
            cached_defs = json.load(f)

            return {name: from_dict(SyscallDefinition, data) for name, data in cached_defs.items()}
    else:
        return None
    return {}

def save_defs_to_cache(definitions: dict) -> None:
    cache_file_path = os.path.expanduser("~/.cache/rsyscaller/syscall_definitions")
    os.makedirs(os.path.dirname(cache_file_path), exist_ok=True)  # Create directories if they do not exist
    with open(cache_file_path, "w") as f:
        # json.dump(asdict(definitions), f)
        json.dump({name: asdict(data) for name, data in definitions.items()}, f)

def find_syscall_definitions(kernel_source_dir):
    # Load existing definitions from cache
    # cached_defs = load_defs_from_cache()
    # Temporarily disable caching
    cached_defs = None
    if cached_defs is not None and cached_defs != {}:
        syscall_map.update(cached_defs)  # Update the syscall_map with cached definitions
        return syscall_map

    # Walk through the kernel source directory
    for root, _, files in os.walk(kernel_source_dir):
        for file in files:
            if file.endswith(".c"):  # Only consider C source files
                file_path = os.path.join(root, file)
                with open(file_path, "r") as f:
                    lines: list[str] = f.readlines()
                    definitions: list[SyscallDefinition] = get_syscall_definitions(
                        lines
                    )
                    syscall_map.update({d.name: d for d in definitions})

    # Save the current definitions to cache
    save_defs_to_cache(syscall_map)

    return syscall_map


def get_buffer_arguments(syscall_name: str, 
                         kernel_source_dir: Optional[str] = None):
    global syscall_map
    if len(syscall_map) == 0:
        assert kernel_source_dir
        syscall_map = find_syscall_definitions(kernel_source_dir)

    if syscall_name.startswith("sys_"):
        syscall_name = syscall_name[4:]

    assert (
        syscall_name in syscall_map
    ), f"Syscall {syscall_name} is not found in definitions map"

    definition: SyscallDefinition = syscall_map[syscall_name]

    return get_buf_idxs(definition.signature_str)


if __name__ == "__main__":
    kernel_sources = f"{find_git_root()}/linux"
    syscall_definitions = find_syscall_definitions(kernel_sources)

    # Example usage
    syscall_name_to_check = sys.argv[
        2
    ]  # Replace with the desired syscall name, such as read
    buffer_arguments = get_buffer_arguments(syscall_name_to_check)

    if buffer_arguments:
        print(
            f"The buffer argument for syscall '{syscall_name_to_check}' is: {buffer_arguments}"
        )
    else:
        print(f"No buffer argument found for syscall '{syscall_name_to_check}'.")

import sys
from typing import Set, List, Dict
from resolve_syscall import resolve_syscall_name, syscall_exists
from fetch_buffer_idx import get_buffer_arguments, find_syscall_definitions

N_SYSCALLS = 1000
SYSCALL_HANDLER_TEMPLATE = """
__attribute__((__unused__)) static int handle_syscall_<SYSCALL_NUM>(struct kprobe* kp, struct pt_regs *regs, int buf_arg_idx, int buf_size_arg_idx) {
  return handler_entry_wrapper(<SYSCALL_NUM>, kp, regs <BUF_ARG_IDX_PARAMS>);
}
"""
OUT_FILE = "handler_wrappers.h"



def generate_handler_wrapper(syscall_num: int, kernel_sources: str) -> str:
    if not syscall_exists(syscall_num):
        return ""

    syscall_name = resolve_syscall_name(syscall_num)

    if syscall_name == "Unknown":
        return ""

    try: 
        buf_arg_idx, buf_size_arg_idx = get_buffer_arguments(syscall_name, kernel_sources)
    except AssertionError as e:
        raise AssertionError(f"Failed to fetch buffer args for syscall {syscall_num}: {e}")

    buf_arg_params = f"{buf_arg_idx}, {buf_size_arg_idx}"

    return SYSCALL_HANDLER_TEMPLATE.replace("<SYSCALL_NUM>", str(syscall_num)).replace(
        "<BUF_ARG_IDX_PARAMS>", buf_arg_params
    )

def generate_union_variant_fetcher(type_defs: Set[str]) -> str:
    # macro_defs: list[str] = [x.upper().replace(" ", "") for x in type_defs]
    counter: int = 0
    generated: str = ""

    for macro_def in type_defs:
        generated += f"\n#define {macro_def.upper()} {counter}"
        counter += 1        

    switch_cases: list[str] = [f"case {type_def.upper()}: *param = &src->{type_def}; *param_size = sizeof(src->{type_def}); return;" for type_def in type_defs]

    func: str = \
        "void fetch_param_variant(SyscallParam *src, int param_type, void **param, size_t *param_size) {\n" + \
        "\tswitch (param_type) {\n\t\t" + \
        "\n\t\t".join(switch_cases) + \
        "\t}\n" + \
        "\t*param = (void*)&src->char_ptr_type; param_type = sizeof(src->char_ptr_type);\n" + \
        "\n}"

    generated += "\n" + func + "\n"

    return generated
         

def generate_param_types_union(syscall_definitions: dict) -> str:
    # syscall name -> count / union type
    param_types_dict: dict[str, tuple[int, str]] = {}
    # type -> type name
    arg_type_names: dict[str, str] = {} 

    for d in syscall_definitions.values():
        for arg in d.arguments:

            arg_type_real: str = arg.type 
            ptr_suffix: str = ""

            if arg.is_ptr:
                arg_type_real += " *"
                ptr_suffix = "_ptr"

            arg_type_name: str = f"{arg.type.replace(' ', '_')}{ptr_suffix}_type"
            arg_type_names[arg_type_real] = arg_type_name
            union_member = f"\t{arg_type_real} {arg_type_name};"

            arg_type_count: int = 0
            if arg_type_real in param_types_dict:
                arg_type_count = param_types_dict[arg_type_real][0]
            arg_type_count += 1

            # Perf sucks here, but idc for compile-time
            param_types_dict[arg_type_real] = (arg_type_count, union_member)

    sorted_types_dict: Dict = dict(sorted(param_types_dict.items(), key=lambda x: x[1][0], reverse=True))
    sorted_type_names: List[str]  = [arg_type_names[x] for x in sorted_types_dict.keys()]
    union_members: List[str] = [x[1] for x in sorted_types_dict.values()]

    generated = "\ntypedef union {\n"
    generated += "\n".join([x for x in union_members]) + "\n} SyscallParam;\n"
    generated += generate_union_variant_fetcher(sorted_type_names)
    
    
    return generated

def main():
    kernel_sources = "/home/dta/linux"
    # kernel_sources = sys.argv[1]
    syscall_map = find_syscall_definitions(kernel_sources)

    funcs: List[str] = [generate_handler_wrapper(i, kernel_sources) for i in range(N_SYSCALLS + 1)]
    funcs = [x for x in funcs if x != ""]
    
    union = generate_param_types_union(syscall_map)

    with open(OUT_FILE, "w+") as f:
        f.write(union)
        f.write("".join(funcs))

if __name__ == "__main__":
    main()
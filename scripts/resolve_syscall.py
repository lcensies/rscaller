import os
import sys
import re

script_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
syscall_table_file = os.path.join(script_dir, "files/syscall_64_5_4.tbl")

SYSCALL_TABLE = {}


def load_syscall_table(file_path):
    syscall_table = {}

    with open(file_path, "r") as file:
        for line in file.readlines():
            if line.startswith("#"):
                continue

            match = re.match(r"(\d+)\s+(\w+)\s+(.+)\s+(sys_\w+)", line)
            if match:
                syscall_number: int = int(match.group(1))
                syscall_name: str = match.group(4)[4:]
                syscall_table[syscall_number] = syscall_name

    return syscall_table


SYSCALL_TABLE = load_syscall_table(syscall_table_file)


def syscall_exists(syscall_number: int) -> bool:
    return syscall_number in SYSCALL_TABLE


def resolve_syscall_name(syscall_number) -> str:
    name: str = SYSCALL_TABLE[syscall_number]
    return name


def main(syscall_number):
    syscall_name = resolve_syscall_name(syscall_number)
    print(syscall_name)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        syscall_number = int(sys.argv[1])
        main(syscall_number)
    else:
        print("Please provide a syscall number as a command line argument.")

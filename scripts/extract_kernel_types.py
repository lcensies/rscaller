import re
from pathlib import Path
from typing import Optional, List, Set
import fnmatch
import os
import sys
from utils import find_git_root

class KernelTypeExtractor:
    def __init__(self, kernel_sources: str, architecture: str = "x86"):
        self.definitions = []
        self.kernel_sources = kernel_sources
        self.architecture = architecture

    def parse_code(self, kernel_source_code: str):
        # Regex patterns for matching structs and typedefs
        struct_pattern = r'struct\s+(\w+)\s*{([^}]*)};'
        typedef_pattern = r'typedef\s+(\w+|\s*\*\s*\w+)\s+(\w+);'

        # Find structs
        for match in re.finditer(struct_pattern, kernel_source_code):
            struct_name = match.group(1)
            members = match.group(2).strip().split(';')
            struct_def = f"struct {struct_name} {{\n"
            for member in members:
                if member.strip():  # Avoid empty declarations
                    struct_def += f"    {member.strip()};\n"
            struct_def += "};"
            self.definitions.append(("struct", struct_def))
        
        # Find typedefs
        for match in re.finditer(typedef_pattern, kernel_source_code):
            typedef_type = match.group(1).strip()
            typedef_name = match.group(2).strip()
            typedef_str = f"typedef {typedef_type} {typedef_name};"
            self.definitions.append(("typedef", typedef_str))

    def parse(self):
        header_files = self.get_header_files()

        for header in header_files:
            # print(f"Extracting definitions from {header}")
            with open(header) as f:
                code = f.read()
                extractor.parse_code(code)

    def get_header_files(self) -> List[str]:
        header_files: List[str] = []
        
        if self.kernel_sources.endswith(".h"):
            header_files = [self.kernel_sources]
        else:
            for root, dirs, files in os.walk(self.kernel_sources):
                for filename in fnmatch.filter(files, '*.h'):
                    header_files.append(os.path.join(root, filename))

        def headers_filter(header: str):
            for x in ["driver", "sound"]:
                if x in header:
                    return False
            if "arch" in header and not self.architecture in header:
                return False
            return True

        header_files = [file for file in header_files if headers_filter(file)]

        return header_files

    def fetch_definitions(self,  filters: Optional[List[str]] = None):
        definitions: List[str] = []
        fetched_types: Set[str] = set()

        if filters is None:
            definitions = [x[1] for x in self.definitions]
        else:
            unique_filters = list(set(filters))

            for definition in self.definitions:
                def_type: str = definition[0]
                if def_type == "typedef": 
                    type_name: str = definition[1].split(" ")[1]
                else:
                    type_name: str = ' '.join(definition[1].split(" ")[0:2])

                if type_name in unique_filters and type_name not in fetched_types:
                    definitions.append(definition[1])
                    fetched_types.add(type_name)
            

        
        return definitions
        


kernel_sources = f"{find_git_root()}/linux"
extractor: KernelTypeExtractor = KernelTypeExtractor(kernel_sources)
extractor.parse()

filters = [ "compat_size_t"]
defs = extractor.fetch_definitions(filters)

for definition in defs:
    print(definition)

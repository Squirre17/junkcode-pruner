from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from typing import List
ks = Ks(KS_ARCH_X86, KS_MODE_64)
from loguru import logger

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
cs = Cs(CS_ARCH_X86, CS_MODE_64)

class Asm:
    '''

    '''
    @staticmethod
    def mnemonic(inst: str) -> List[bytes]:
        
        inst, length = ks.asm(inst)
        # logger.debug(",".join(
        #     list(map(lambda x: hex(x), inst))
        # ))
        # print(ptrlib.disasm(inst))
        return inst[0:length]

class Disasm:

    @staticmethod
    def disasm(text: bytes, addr: int) -> List[int]:
        # breakpoint()
        all_insts = []
        for inst in cs.disasm(text, addr):
            # logger.debug(hex(inst.address))
            # breakpoint()
            all_insts.append(inst.address)

        return all_insts
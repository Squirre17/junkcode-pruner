from loguru import logger
from typing import List, Tuple
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from jcp.xasm import Asm

class JjnCheck:
    '''
    remove junkcode like 
        je-jne
        jz-jnz
    '''
    JE  : List[bytes] = Asm.mnemonic("je 3")
    JNE : List[bytes] = Asm.mnemonic("jne 3")
    JZ  : List[bytes] = Asm.mnemonic("jz 3")
    JNZ : List[bytes] = Asm.mnemonic("jnz 3")
    checklist = [
        "je", "jne", "jz", "jnz"
    ]
    
    @staticmethod
    def is_pair(a: bytes, b: bytes) -> bool:

        checkee = {a[0], b[0]}
        checks = ({JjnCheck.JE[0], JjnCheck.JNE[0]}, {JjnCheck.JZ[0], JjnCheck.JNZ[0]})

        if (a[0] == b'\x74' and b[0] == b'\x75') or (a[0] == b'\x75' and b[0] == b'\x74'):
            breakpoint()
            
        if checkee in checks:
            return True
        return False
    
    # @staticmethod
    # def patch_function(start: int, end: int) -> None:
    #     inst: str = idc.GetDisasm(start)

    #     logger.debug(idc.create_insn(start))

    #     cur_addr = start

    #     while cur_addr != end:
    #         #对ea所在地址的机器码进行反汇编，返回指令长度
    #         # inst_len = idc.create_insn(cur_addr) 这条会crash掉程序
    #         # idc.inst
    #         logger.debug("AAAAAAAAAAAAA")
    #         next_addr = idc.next_head(cur_addr)
    #         cur_inst : str = idc.GetDisasm(cur_addr)
    #         next_inst: str = idc.GetDisasm(next_addr)
    #         logger.debug(cur_inst)

    #         if JjnCheck.is_pair(cur_inst, next_inst):
    #             dst1 = idc.print_operand(cur_inst, 0) 
    #             dst2 = idc.print_operand(next_inst, 0) 
    #             logger.debug(dst1)
    #             logger.debug(dst2)
    #             return 
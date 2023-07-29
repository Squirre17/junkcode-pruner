import angr
from loguru import logger
from jcp.xasm import Disasm, Asm
from typing import List
from jcp.diff import SecDiff
from jcp.bin import Binary
from jcp.checker import JjnCheck

# TODO: move
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
cs = Cs(CS_ARCH_X86, CS_MODE_64)


def check_next_node_is_junk(addr: int, next_addr: int, bin: Binary):
    '''
    40119a:       74 03                   je     40119f <label2>
    40119c:       75 01                   jne    40119f <label2>
    '''
    # TODO: make a new cfg node class with instructions
    code1 = bin.code(addr, 2)
    code2 = bin.code(next_addr, 2)
        
    return JjnCheck.is_pair(code1, code2)


class Cfg:

    def __init__(self, fname: str, bin: Binary) -> None:

        proj = angr.Project(fname, load_options={
            "auto_load_libs" : False
        })

        # render_cfg(proj, "test", "test.cfg")

        cfgfast: angr.analyses.CFGFast = proj.analyses.CFGFast(
            normalize=True, force_complete_scan=False
        )

        self.cfg  = cfgfast
        self.proj = proj
        self.bin  = bin

    def inst_addrs(self, text: SecDiff.Region) -> List[SecDiff.Region]:

        ret = []
        skip_junknode_addrs = []
        for node in self.cfg.nodes():

            
            # if self.cfg.graph.in_degree(node) == 0:

            #     end = text.addr + text.size
            #     start = text.addr
            #     if node.addr >= start and node.addr < end:

            #         logger.debug("seems like I found it at {:x}".format(node.addr))
            #         continue
            next_node_is_junk = False

            inst_addrs = [addr for addr in node.instruction_addrs]
            # breakpoint()
            inst_nr = len(inst_addrs) # NOTE: 有可能为1
            inst_addrs.append(node.addr + node.size) # extra

            inst_regions: List[SecDiff.Region] = []
            for i in range(inst_nr):
                size = inst_addrs[i+1] - inst_addrs[i]
                inst_regions.append(SecDiff.Region(inst_addrs[i], size))


            for i in range(inst_nr):
                # 越界一个指令问题并不大
                if check_next_node_is_junk(inst_addrs[i], inst_addrs[i+1], self.bin):
                    next_node_is_junk = True
            
            if next_node_is_junk:

                skip_at_addr = None
                '''
                这里有三个基本块
                jz 0x1234
                jnz 0x1234
                .bytes 0x0721 
                '''
                for node in self.cfg.nodes():
                    if node.addr == inst_addrs[i+1]:
                        skip_at_addr = node.addr + node.size
                        
                if skip_at_addr is None:
                    raise Exception("unreachable")
                
                skip_junknode_addrs.append(skip_at_addr)
                # breakpoint()

            ret += inst_regions
        
        for node in self.cfg.nodes():
            if node.addr in skip_junknode_addrs:
                logger.info("skip at {:x}".format(node.addr))
                start, end = node.addr, node.addr + node.size
                ret = [r for r in ret if r.addr < start or r.addr >= end]

        [logger.debug(r) for r in ret if r.addr >= 0x40115b and r.addr < 0x401184]
        return ret

    def find_skip_regions(self, text: SecDiff.Region) -> List[SecDiff.Region]:

        ret = []
        skip_junknode_addrs = []
        for node in self.cfg.nodes():

            next_node_is_junk = False

            inst_addrs = [addr for addr in node.instruction_addrs]
            # breakpoint()
            inst_nr = len(inst_addrs) # NOTE: 有可能为1
            inst_addrs.append(node.addr + node.size) # extra

            inst_regions: List[SecDiff.Region] = []
            for i in range(inst_nr):
                size = inst_addrs[i+1] - inst_addrs[i]
                inst_regions.append(SecDiff.Region(inst_addrs[i], size))


            for i in range(inst_nr):
                # 越界一个字节问题并不大
                if check_next_node_is_junk(inst_addrs[i], inst_addrs[i+1], self.bin):
                    next_node_is_junk = True
            
            if next_node_is_junk:

                skip_at_addr = None
                '''
                这里有三个基本块
                jz 0x1234
                jnz 0x1234
                .bytes 0x0721 
                '''
                for node in self.cfg.nodes():
                    # 找到第二个基本块 
                    if node.addr == inst_addrs[i+1]:
                        skip_at_addr = node.addr + node.size
                        
                if skip_at_addr is None:
                    raise Exception("unreachable")
                
                skip_junknode_addrs.append(skip_at_addr) # 第三个基本块 也就是junk块的开头
                # breakpoint()

            ret += inst_regions
        
        skip_regions: List[SecDiff.Region] = []
        for node in self.cfg.nodes():
            if node.addr in skip_junknode_addrs:
                logger.info("skip at {:x}".format(node.addr))
                # start, end = node.addr, node.addr + node.size
                skip_regions.append(SecDiff.Region(node.addr, node.size))

        return skip_regions
from loguru import logger
from typing import List, Tuple, Set, Type
from jcp.checker import JjnCheck
from jcp.diff import SecDiff
import click
from pathlib import Path
from jcp.cfg import Cfg
from jcp.bin import Binary


def hexlist(l: List[SecDiff.Region]):
    logger.debug("[ " + ",".join(
        list(map(lambda x : hex(x.addr), l))
    ) + " ]")

# ----------------------------------------------------------
# "./samples/build/linux/x86_64/debug/jz-jnz"
@click.command()
@click.option('--path', '-p', required=True, type=Path, help='Path to junkcode binary.', )
@click.option('--output', '-o', required=False, type=Path, help='Path to output binary.', )
def main(path: Path, output: Path) -> None:

    if output is None:
        output = Path("./patch")

    bin = Binary(path, output)
    cfg = Cfg(path, bin)# TODO: Cfg should generate by bin through some func

    skip_regions: Set[Type["SecDiff.Region"]] = set(cfg.find_skip_regions(bin.text))
    logger.debug(skip_regions)
    for skip_reg in skip_regions:
        bin.patch_nop_back(skip_reg.addr, skip_reg.size)

main()

# Disasm.mnemonic("jz 3")

# fnidx = ida_funcs.get_fun(function_name)
# ida_funcs.getn_func
# logger.debug(ida_funcs.get_func("add_with_junk").start_ea)
# JjnCheck.patch_function(0x1188, 0x1197)
# logger.debug("AAAAAAAAAA")

# fname = 
# logger.debug(cfg.inst_addrs())

# junkcode_regions: List[SecDiff.Region] = []

# for sec in bin.sections:
#     # 此处不能append 否则是附加一个链表对象
#     sec_cfg_regs = [
#         reg for reg in cfg_inner_regs 
#             if (sec.addr <= reg.addr) and (reg.addr < sec.addr + sec.size)
#     ]
#     junkcode_regions += SecDiff.diff(sec.addr, sec.size, sec_cfg_regs, bin.text)

# breakpoint()

# non_overlap_inst_addrs = list(all_inst_addrs - cfg_inner_regs)
# hexlist(junkcode_regions)
# breakpoint()
# logger.debug(non_overlap_inst_addrs)
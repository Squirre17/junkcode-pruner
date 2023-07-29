from loguru import logger
from typing import List, Tuple
import sys

# 模型抽象
'''
有一条n米长的跑道

有x个数据结构[start, len] 代表着从这个跑道的start处 染色len米

要求返回[start, len]的数组 代表着未染色的区域

例子：

10米长跑道 染色 [1, 2] [8, 1]

应当返回

[0, 1], [2, 6], [9, 1]

其中[start, len] 其实就是[指令地址 指令长度] 
跑道其实就是一个section的长度
排序过后就只有一个
'''

        
        
class SecDiff:
    '''
    通过用cfg中的指令对目标段染色 就能知道哪些是花指令区域
    '''

    class Region:
        __slots__ = ["addr", "size"]
        def __init__(self, addr: int, size: int) -> None:
            self.addr = addr
            self.size = size

        def __repr__(self) -> str:
            return "<{:x} {:d}>".format(self.addr, self.size)
        
    @staticmethod
    def diff(sec_addr: int, sec_size: int, regions: List[Region], text: Region) -> List[Region]:

        if sec_addr != text.addr:
            return []
        
        logger.debug("enter diff")
        
        start = sec_addr
        # ascending order for O(n) complexity
        regions = sorted(regions, key=lambda r: r.addr)

        junkcode_regions: List[SecDiff.Region] = []

        for r in regions:

            if r.addr < start:
                logger.debug(f"[{r.addr} {r.size}] shouldn't low than {start}")
                sys.exit(1)

            if r.addr == start:
                start += r.size
                try:
                    assert start <= sec_addr + sec_size
                except AssertionError:
                    breakpoint()
                
            if r.addr > start:
                # 出现花指令区域
                junkcode_regions.append(SecDiff.Region(start, r.addr - start))
                start = r.addr + r.size
        
        return junkcode_regions

            


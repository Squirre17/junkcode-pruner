# TODO
- add support to pie
# usage

prune junkcode automatically
```shell
py main.py -p "./samples/build/linux/x86_64/debug/jz-jnz"
```

# 心路历程

最开始想用sh_addr作为cs.disasm的传入 发现不行 在pie下不一样

最开始想用.text节去生成所有指令 但是发现cfg生成的指令比所有指令还多 然后发现还有init等段是有可执行权限的 

第二次有遇到问题 由于花指令是天然抗线性汇编扫描的 下面的命令会被capstone获取不到 是cfg有all_insts没有的 不能采取指令指令一一映射取差集的关系去获取到花指令块
`[ 0x401178,0x4011a2,0x401175,0x40119f ]`
```
0000000000401175 <label>:
        "jz label;"
        "jnz label;"
        ".byte 0xe8;"    // call 指令，后面加4bytes的地址偏移，因此导致反汇编器不能正常识别
        "    label:"
    );
    c = a + b;
  401175:       8b 55 ec                mov    edx,DWORD PTR [rbp-0x14]
  401178:       8b 45 e8                mov    eax,DWORD PTR [rbp-0x18]
  40117b:       01 d0                   add    eax,edx
  40117d:       89 45 fc                mov    DWORD PTR [rbp-0x4],eax
    return c;
  401180:       8b 45 fc                mov    eax,DWORD PTR [rbp-0x4]
}
  401183:       5d                      pop    rbp
  401184:       c3                      ret    
```

后面貌似发现 花指令也在cfg中 想根据入度为0去去除 但是_start 啊 plt中又有很多其他的入度为0的 ，。。。

而且发现一个更可怕的事情 他入度为1 是jnz里导致的
```shell
(Pdb++) p hex(node.addr)
'0x401174'
(Pdb++) p self.cfg.graph.in_degree(node)
1
```
类似于这样
```
------
| jz |
-----------
|         |
↓         ↓
    --------
    | jnz  | ------->
    --------
       |
       ↓
    --------
    | junk |
    --------
```

在cfg中则出现了花指令的错误节点
```

2023-07-28 20:21:43.375 | DEBUG    | jcp.cfg:<listcomp>:83 - <401170 2>
2023-07-28 20:21:43.375 | DEBUG    | jcp.cfg:<listcomp>:83 - <401172 2>
2023-07-28 20:21:43.375 | DEBUG    | jcp.cfg:<listcomp>:83 - <401179 6>  <<- 这些都是因为对0xe8 错误解释带来的格外错误汇编node
2023-07-28 20:21:43.375 | DEBUG    | jcp.cfg:<listcomp>:83 - <40117f 1>
2023-07-28 20:21:43.375 | DEBUG    | jcp.cfg:<listcomp>:83 - <401180 3>
2023-07-28 20:21:43.375 | DEBUG    | jcp.cfg:<listcomp>:83 - <401183 1>
2023-07-28 20:21:43.375 | DEBUG    | jcp.cfg:<listcomp>:83 - <401175 3>
2023-07-28 20:21:43.375 | DEBUG    | jcp.cfg:<listcomp>:83 - <401178 1>
2023-07-28 20:21:43.375 | DEBUG    | jcp.cfg:<listcomp>:83 - <401174 1>  <<- 

  401169:       c7 45 fc 00 00 00 00    mov    DWORD PTR [rbp-0x4],0x0
    asm(
  401170:       74 03                   je     401175 <label>
  401172:       75 01                   jne    401175 <label>
  401174:       e8                      .byte 0xe8

0000000000401175 <label>:
        "jz label;"
        "jnz label;"
        ".byte 0xe8;"    // call 指令，后面加4bytes的地址偏移，因此导致反汇编器不
能正常识别
        "    label:"
    );
    c = a + b;
  401175:       8b 55 ec                mov    edx,DWORD PTR [rbp-0x14]
  401178:       8b 45 e8                mov    eax,DWORD PTR [rbp-0x18]
  40117b:       01 d0                   add    eax,edx
  40117d:       89 45 fc                mov    DWORD PTR [rbp-0x4],eax
    return c;
  401180:       8b 45 fc                mov    eax,DWORD PTR [rbp-0x4]
}
  401183:       5d                      pop    rbp
  401184:       c3                      ret   
```

最终的方式还是用指令扫描去做的
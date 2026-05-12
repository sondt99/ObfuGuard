# ObfuGuard

## REQUIREMENT
- Library: asmjit, zydis, keystone, capstone, lief

```bash
vcpkg install capstone:x64-windows
vcpkg install keystone:x64-windows
vcpkg install lief:x64-windows
vcpkg install asmjit:x64-windows
vcpkg install zydis:x64-windows
```

- PE file and PDB file of the program to be obfuscated.


## Control Flow Flattening


### Technique

- Traverse all instructions of the function to create blocks. Blocks are built starting from destination points of conditional jump instructions. The end of blocks will be natural termination points: either a jump instruction that is not a function call, or a ret instruction, or a destination point from conditional jump instructions.

- Traverse all blocks, if the last instruction of a block is a conditional jump, set the position of the block that the conditional jump jumps to in block_dst. Set the next_block attribute of the current block to current_block_id+1.

- Shuffle the vector containing the blocks. Use rax as a state variable to transfer flow through dispatcher and create control structure to perform flow flattening.


### PoC


![before cff](/PoC/cff/before.png)

- Before flattening, the function has basic flow structure as above: A->B or C -> D. The goal of this flow flattening is to create a control structure that transfers flow between blocks A,B,C,D through dispatcher instead of the original linear flow execution with unchanged effectiveness. The target to be achieved is as follows:

![target](/PoC/cff/target.png)

- After performing flow flattening, load the entire obtained PE file into IDA software to check the results.

![CFG after flattening](/PoC/cff/CFG_after.png)


- Based on the obtained Control-flow graph, the program structure has been transformed through the state variable which is the rax register, and continuously transfers flow through instructions `cmp eax,0`, `cmp eax,2`, `cmp eax,3`, `cmp eax,1`. Tracing the flows corresponding to eax leads to block A, block B, Block C, Block D as expected.


- Continue to verify the program effectiveness through the pseudocode obtained when decompiling:

```C
__int64 __fastcall sub_1400292F5(char a1)
{
  __int64 v5; // rax
  _QWORD *v6; // rbp
  __int64 v7; // rdi
  int v8; // eax
  _QWORD v15[26]; // [rsp-D0h] [rbp-1A8h] BYREF
  __int64 v16; // [rsp+0h] [rbp-D8h]
  char v17; // [rsp+10h] [rbp-C8h]

  v16 = v5;
  __asm { pushf }
  v8 = 0;
  while ( 1 )
  {
    while ( v8 == 2 )
    {
      __asm { popf }
      v16 = sub_140011217();
      __asm { pushf }
      v8 = 3;
    }
    if ( v8 )
      break;
    __asm { popf }
    v17 = a1;
    v16 = (__int64)v6;
    v15[25] = v7;
    v6 = v15;
    ((void (__fastcall *)(void *))sub_1400113F7)(&unk_140023076);
    ((void (__fastcall *)(_QWORD, const char *))sub_140011087)(std::cout, "Block A\n");
    _CF = 0;
    _OF = 0;
    _ZF = v17 == 0;
    _SF = 0;
    if ( v17 )
    {
      __asm { pushf }
      v8 = 1;
    }
    else
    {
      __asm { pushf }
      v8 = 2;
    }
  }
  if ( v8 == 3 )
  {
    __asm { popf }
    return v16;
  }
  else
  {
    __asm { popf }
    return sub_1400112C1();
  }
}
```
 
- Based on the obtained pseudocode, the program structure also easily shows changes. With the state variable v8 (representing rax), the if statements check the values of the state variable to transfer flow into block A, sub_1400112c1 (), sub_140011217() and return. When tracing along this flow, the result shows that this program structure performs flow transfer through variable v8 to blocks A, block B, block C, block D as expected.





## Junk Code Injection
### Techique

- Background technique - Trampoline: trampoline technique performs changing program flow through indirect jumping functions to the source code part that needs to be executed.

- First, to create space for inserting junk instructions, the program will use trampoline technique to relocate the original function of the selected function to a newly created section to perform junk code insertion. Relocating the original function to a new section will allow the program to intervene more in inserting into functions without affecting the structure of the remaining parts of the binary.

- The program creates a new empty section as memory area where the function to be obfuscated will be relocated to. Read all instructions in the selected function into buffer; turn the memory area of the initially selected function into an indirect jump function to the beginning of the newly created section area (trampoline technique).

- The program traverses the buffer and writes code from the buffer into the newly created section. For each instruction written from the buffer, one or more junk code instructions randomly selected from the program's junk code collection are written after it. When finished, the original function has been inserted between junk code segments.


### PoC

![before junkcode](PoC/junkcode/junkcode_before.png)

- Before performing junk code insertion, the function binary is located at RVA 0x12380. All instructions of the function are very clear and logically continuous. The goal of junk code insertion is that after inserting junk code, the function will have junk instructions inserted between the original binary instructions. These instructions increase the difficulty of software reverse engineering but are completely harmless to the overall program logic.

- After performing junk code insertion, load the obtained PE into IDA software to verify effectiveness:


![origin_rva_after](PoC/junkcode/origin_rva_after.png)

- At the original RVA of the selected function, it can be seen that the code segment in the function is simply a jump instruction to the new section. All remaining parts of the function are patched with nop instructions according to the trampoline technique. Tracing this jmp instruction shows that the original function code has been successfully relocated to the new section area exactly as the trampoline technique.

![binary after](PoC/junkcode/binary_after.png)

- At the section area where the original function was relocated to, it can be seen that the binary of the original function has been inserted between many junk instructions that do not affect the overall program logic such as `mov rdx, rdx`, `lea rbx, rbx`,... These instructions do not affect program logic but confuse the binary code for analysts. The obfuscating effectiveness of the obtained file is as expected.




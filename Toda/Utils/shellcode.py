from pwn import *
MAP_PRIVATE=2
STAGE_ADDR=0x100000
STAGE_SIZE=0x4000
JUMP_SIZE=10
HEX_TABLE_ADDR=STAGE_ADDR+STAGE_SIZE-0x100
TOHEX_FUNC_ADDR=STAGE_ADDR+STAGE_SIZE-0x200
TEMP_BUF=STAGE_ADDR+STAGE_SIZE-0x800

def recover_ehs(addr,recover_data,offset):
    data_len=len(recover_data)

    recover_template=f"""
        mov rcx,{data_len};
        mov rdi,[rsp];
        sub rdi,0x82;
        lea rsi,[rip+tdata];
        rep movsb;
        pop rax;

        lea r8,[rax{str(offset)}];
        push r8;
        pop r8;
        {RECOVER_REG}
        mov r8,[rsp-{16*8+8}]
        push r8
        ret;

    tdata:
    


    """
    context.arch="amd64"
    tdata=b""
    for i in recover_data:
        tdata+=p8(i)
    return asm(recover_template)+tdata

RECOVER_EHS=f"""


"""

INIT_STAGE=f"""
push 0x0070;
mov rax, 0x616d5f6567617473;
push rax;
mov rax,2;
mov rdi,rsp;
mov rsi,0;
syscall;

mov r8,rax;
mov rax,9;
mov rdi,{STAGE_ADDR};
mov rsi,{STAGE_SIZE};
mov rdx,7;
mov r10,2;
mov r9,0;
syscall;

mov rdi,3
mov rax,3
syscall

pop rax;
pop rax;
"""

ENTRY_STAGE=f"""
mov rax,{STAGE_ADDR}
call rax

"""

SAVE_REG="""
push rax; push rbx; push rcx; push rdx;
push rsi; push rdi; push rbp;
push r8; push r9; push r10; push r11;
push r12; push r13; push r14; push r15;
pushfq;
"""

RECOVER_REG="""
popfq;
pop r15; pop r14; pop r13; pop r12;
pop r11; pop r10; pop r9; pop r8;
pop rbp; pop rdi; pop rsi;
pop rdx; pop rcx; pop rbx; pop rax;
"""


TOHEX_FUNCTION=f"""
    push rbp;
    mov rbp, rsp;
    push rdx;
    push rsi;
    push rdi;
    mov rcx,0
into:
    cmp rdx,0
    je end
    mov r14,rcx
    lea r14,[rcx*2]
    xor rbx,rbx
    mov bl,byte ptr [rdi+rcx]
    shr rbx,4
    lea rax, [{HEX_TABLE_ADDR}+rbx]
    mov al,byte ptr [rax]
    mov byte ptr [rsi+r14],al

    mov bl,byte ptr[rdi+rcx]
    and rbx,0xf
    lea rax, [{HEX_TABLE_ADDR}+rbx]
    mov al,byte ptr [rax]
    mov byte ptr [rsi+r14+1],al
    add rcx,1
    sub rdx,1
    jmp into
end:
    leave;
    ret;
"""


PRINTREG=f"""
    mov rsi,{STAGE_ADDR};
    mov [rsi],[replace];
    mov rdx,8
    mov rax,1
    syscall

"""
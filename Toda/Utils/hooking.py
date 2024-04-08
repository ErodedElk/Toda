from Toda.Utils.shellcode import *

def split_string_by_length(s, length):
    return [s[i:i+length] for i in range(0, len(s), length)]

def round_up(value,align):
    if value%align==0:
        return value
    else:
        return value+(align-(value%align))

class hook_base:
    def __init__(self):
        return 
    def serialize(self):
        return asm(self.template)

class printreg(hook_base):
    def __init__(self,reg):
        super(printreg,self).__init__()
        self.template=f"""
            push {reg};

            bswap {reg};
            mov [{TEMP_BUF}],{reg};
            mov rdi,{TEMP_BUF};
            mov rsi,{TEMP_BUF+8};
            mov rdx,8;
            mov r14,{TOHEX_FUNC_ADDR};
            call r14;
            mov rax,1;
            mov rdi,1;
            mov rsi,{TEMP_BUF+8};
            mov rdx,16;
            syscall
            mov byte ptr [{TEMP_BUF}],10;
            mov rdi,1;
            mov rsi,{TEMP_BUF};
            mov rdx,1;
            mov rax,1;
            syscall;
            pop rax;
        """
        
class printstr(hook_base):
    def __init__(self,input_str):
        super(printstr,self).__init__()
        input_len=len(input_str)
        div_res=input_len%8
        temp_input=input_str[::-1]
        first=temp_input[:div_res]
        res=temp_input[div_res:]
        res=split_string_by_length(res,8)
        self.template=""
        self.template+="""
            push rbp;
            mov rbp,rsp;
        """
        if len(first)==0:
            pass
        else:
            self.template+=f"""
                mov r14,0x{first.hex()};
                push r14;
                """
        for i in res:
            self.template+=f"""
                mov r14,0x{i.hex()};
                push r14;
                """
        self.template+=f"""
            mov rdi,1;
            mov rsi,rsp;
            mov rdx,{input_len};
            mov rax,1;
            syscall
            leave;

            mov byte ptr [{TEMP_BUF}],10;
            mov rdi,1;
            mov rsi,{TEMP_BUF};
            mov rdx,1;
            mov rax,1;
            syscall;

        """

class raw_shellcode(hook_base):
    def __init__(self,sc):
        super(printstr,self).__init__()
        self.template=sc

class mhexdump(hook_base):
    def __init__(self,addrorreg,length):
        super(mhexdump,self).__init__()
        length=round_up(length,0x10)
        self.template=f"""
            mov rdi,{addrorreg};
            mov rsi,{TEMP_BUF};
            mov rdx,{length};
            mov r14,{TOHEX_FUNC_ADDR};
            call r14;
            mov rsi,{TEMP_BUF};
            mov rdi,1;
            mov rdx,{length};
            mov rax,1;
            syscall
        """


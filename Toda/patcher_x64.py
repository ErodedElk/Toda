from subprocess import *
import sys, os
from pwn import *
from Toda.Utils.shellcode import *
import capstone

def round_up(value,align):
    if value%align==0:
        return value
    else:
        return value+(align-(value%align))

class patcher:
    def __init__(self,filename):
        self.filename=filename
        self.elf=ELF(filename)
        context.arch = 'amd64'
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True
        self.hook_list={}
        self.stage_base=STAGE_ADDR
        self.stage_offset=0
        self.offset=0
        file=open("./test/stage_map","wb+")
        self.stage_map=file
    
    def logh(self,key,value):
        log.success(key + '===>' + hex(value))

    def run(self):
        if self.elf.pie == True:
            self.patch_pie_elf()
        else:
            self.patch_nopie_elf()
        
        self.edit_table_rwx()
        self.build_map()

        

    def edit_table_rwx(self):
        demo=self.elf.get_section_by_name('.eh_frame')
        self.write_addr=demo.header.sh_addr
        self.section_size=demo.header.sh_size

        program_table_header_start = self.elf.address + self.elf.header.e_phoff
        num_of_program_table_header = self.elf.header.e_phnum
        size_of_program_headers = self.elf.header.e_phentsize

        for i in range(num_of_program_table_header):
            p_type = self.elf.get_segment(i).header.p_type
            p_flags = self.elf.get_segment(i).header.p_flags
            if p_type == 'PT_LOAD' and p_flags == 4:
                self.elf.write(program_table_header_start + i * size_of_program_headers + 4, p32(7))
                print('edit program_table_element[' + str(i) + '].p_flags===>r_x')

    def patch_pie_elf(self):
        eh_frame_addr = self.elf.get_section_by_name('.eh_frame').header.sh_addr
        self.eh_frame_addr=eh_frame_addr
        
        start_offset = self.elf.header.e_entry
        offset = self.elf.read(start_offset, 0x40).find(b'\x48\x8d\x3d')  # lea rdi,?
        
        offset1 = u32(self.elf.read(start_offset + offset + 3, 4))
        if offset1 > 0x80000000:
            offset1 -= 0x100000000
        main_addr = start_offset + offset + offset1 + 7
        self.main_addr=main_addr

        self.logh("main_addr",main_addr)

        p=disasm(self.elf.read(start_offset + offset, 7))
        s = 'lea rdi,[rip+' + str(hex(eh_frame_addr - (start_offset + offset) - 7)) + '];'
        print(disasm(asm(s)))



        inject_code = self.make_scstage()
        # tail= ''
        # tail+= 'lea r8,[rip' + str(hex(main_addr - (eh_frame_addr + len(inject_code)) - 7)) + '];'
        # tail+= "push r8;"
        # tail+= "mov r8,0;"
        # tail+= 'ret;'
        self.offset=((main_addr - (eh_frame_addr + len(inject_code))))

        save_backup=self.elf.read(eh_frame_addr,len(inject_code))
        self.save_backup=save_backup
        self.elf.write(start_offset + offset, asm(s))
        self.elf.write(eh_frame_addr, inject_code)

    def make_scstage(self):
        stage=b""
        stage+=asm(SAVE_REG)
        stage+=asm(INIT_STAGE)
        stage+=asm(ENTRY_STAGE)

        return stage

    def build_map(self):
        sc=b""

        sc+=recover_ehs(self.eh_frame_addr,self.save_backup,self.offset)
        sc+=asm(RECOVER_REG)
        self.stage_map.write(sc)
        self.offset=0
        self.offset += round_up(len(sc),0x10)

        self.stage_map.seek(STAGE_SIZE-0x200)
        self.stage_map.write(asm(TOHEX_FUNCTION))
        self.stage_map.seek(STAGE_SIZE-0x100)
        self.stage_map.write(b"0123456789abcdef")

    def finish(self):
        self.elf.save(self.filename + '.patch')
        self.stage_map.close()
    
    def hook(self,addr,functions):
        self.hook_list[addr]=self.get_next_hookable()

        temp_data=self.elf.read(addr,0x20)
        now_size=0
        backup_ins=[]
        stage=self.hook_stage(self.hook_list[addr])
        while True:
            instruction = next(self.md.disasm(temp_data, addr+now_size), None)
            backup_ins.append(instruction)

            #print("0x%x:\t%s\t%s" % (instruction.address, instruction.mnemonic, instruction.op_str))
            now_size+=instruction.size
            if now_size>=len(stage):
                break
            temp_data=temp_data[now_size:]
        next_addr=addr+now_size

        #backup_ins=self.elf.read(addr,now_size)
        self.elf.write(addr,stage)

        hook_sc=b""
        hook_sc+=asm(SAVE_REG)
        hook_sc+=asm("push rbp;mov rbp,rsp;")

        for i in functions:
            hook_sc+=i.serialize()
        
        hook_sc+=asm("leave;")
        
        hook_sc+=asm(RECOVER_REG)
        hook_sc+=self.fix_ins(backup_ins,next_addr)
        self.write_map(self.offset,hook_sc)


    def fix_ins(self,inst,next_addr):
        #TODO: fix inst
        all_sc=b""
        all_size=0
        for i in inst:
            print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
            print(i.operands)
            if "rip" in i.op_str:
                demo=f"""
                    mov r14,[rsp];
                    sub r14,10;
                    add r14,{len(i.bytes)+all_size};
                    """
                demo+=i.mnemonic+" "+i.op_str.replace("rip","r14")+";"
                #print(demo)
                all_sc+=asm(demo)
                all_size+=i.size
            elif i.mnemonic == 'call':
                is_absolute = any(op.type == capstone.x86.X86_OP_IMM for op in i.operands)
                print(is_absolute)
                if is_absolute:
                    target_address = i.operands[0].imm-(i.address + i.size )
                    demo=f"""
                    mov r14,[rsp];
                    sub r14,10;
                    add r14,{target_address+i.size};
                    call r14;
                    """
                    print(demo)
                    all_sc+=asm(demo)
                    all_size+=i.size
                else:
                    #TODO: No change? Check!
                    all_sc+=i.bytes
                    all_size+=i.size
            else:
                all_sc+=i.bytes
                all_size+=i.size
        
        template_sc=f"""
            pop r14
            sub r14,10
            add r14,{all_size}
            jmp r14
        """
        return all_sc+asm(template_sc)

    def get_next_hookable(self):
        return self.stage_base+self.offset

    def write_map(self,addr,data):
        self.stage_map.seek(addr)
        self.stage_map.write(data)
        self.offset+=round_up(len(data),0x10)

    def hook_stage(self,addr):
        sc_tmp=f"""
            mov r14,{addr}
            call r14
        """
        return asm(sc_tmp)
        



    def test_stage(self):
        return recover_ehs(0x100,[1,2,3,4,5])
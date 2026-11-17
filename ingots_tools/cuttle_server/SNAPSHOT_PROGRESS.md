# Cuttlefish Snapshot/Restore Progress

Status as of 2026-11-17: **snapshot and restore work end to end on arm64 (`arm_desktop`)**, from
`cuttle-cli` down to Cuttlefish.

- The patched crosvm is installed in all three challenge7 runtimes (see
  [Deployment](#deployment-on-arm_desktop)).
- `cuttle_server` and `cuttle-cli` have snapshot support (see
  [Server and CLI implementation](#server-and-cli-implementation)), verified against real
  Cuttlefish with an isolated test server. **The production service has not been updated or
  restarted yet**; the remaining steps are listed under [Next steps](#next-steps).

No Cuttlefish host-tool rebuild was needed; only crosvm is replaced.

Supporting files live in [`snapshot/`](snapshot/):

- `crosvm-vgic-restore-skip-clear-regs.patch`: the crosvm fix (applies to upstream `09438a730`).
- `crosvm_openwrt_restore_test.sh`: a standalone crosvm snapshot/restore reproducer (no Cuttlefish).
- `snapshot_cycle_test.sh`: one full Cuttlefish snapshot -> mutate -> restore cycle against any
  runtime root, mimicking what the server does.

## Result

Test: challenge7 runtime (`android-15.0.0_r2` images, host package build `13263448`), instance 2,
`HOME=/home/ingots/snaptest/f`, runtime copy at `/home/ingots/snaptest/rt-r2` with crosvm swapped.

| Step | Result |
|---|---|
| Boot with `--snapshot_compatible` | 36 s |
| `snapshot_util_cvd --subcmd=snapshot_take --auto_suspend` | 3.0 s, ~4.6 GB on disk |
| Mutate guest after snapshot (overwrite file, kill process), `stop_cvd` | — |
| `launch_cvd ... --snapshot_path=<snap>` (restore #1) | 16.8 s, `rc=0` |
| Guest state after restore | Killed process back with **same pid**, overwritten file back to pre-snapshot contents, uptime continues from snapshot, no panic/reboot, adb works, `sys.boot_completed=1` |
| Mutate again, stop, restore **the same snapshot** again (restore #2) | 6.4 s, identical state again; restore does not modify snapshot files |

## Required launch flags

```
launch_cvd --snapshot_compatible \
  --gpu_mode=guest_swiftshader \   # auto-detected GPU mode fails assemble_cvd's snapshot check
  --vhost_user_vsock=false \       # vhost_device_vsock lacks VHOST_USER_PROTOCOL_F_DEVICE_STATE
  ... (normal flags)
# restore:
launch_cvd <same flags> --snapshot_path=<snapshot dir>
```

Leave the Wi-Fi access point (OpenWrt VM) enabled: `run_cvd`'s restore path unconditionally
calls the OpenWrt control server to run `service network restart` and `CHECK`-fails (killing the
whole device) if that fails. Disabling the AP (`--ap_kernel_image= --ap_rootfs_image=`) makes
restore fail with `IP address is not found from launcher.log`.

## Root causes (all in crosvm, none in the guest kernel or Cuttlefish)

The crosvm shipped in the host package predates the arm64 snapshot work. Three problems had to be
fixed, found in this order:

1. **vCPU state missing `SP_EL1` and friends** (fixed upstream in crosvm `6a2467b33`, 2025-03-25).
   crosvm enumerated system registers by an ID bit pattern that excludes `SP_EL1`, `ELR_EL1`,
   `SPSR_*`, `FPSR`, `FPCR`. After restore `SP_EL1=0`, so the guest kernel panicked with
   `kernel stack overflow` (`sp : 0000000000000000` in `arch_cpu_idle`). Confirmed by decoding the
   saved `guest_snapshot/guest_vm/vcpu/vcpu0`: `SCTLR_EL1`/`TTBR1_EL1`/`VBAR_EL1` present,
   `SP_EL1`/`ELR_EL1`/`SPSR_EL1`/`FPCR` absent.
2. **vGIC (interrupt controller) not saved at all** (fixed upstream in `35bd2439e` + `69cbac8c1`,
   2025-03). The old snapshot's `irqchip` fragment was literally `null`.
3. **vGIC restore disables every interrupt** (**still present in upstream HEAD `09438a730`,
   2026-11-17**, and in the crosvm pinned by `google/android-cuttlefish`, `597fa65c6`). Found
   and patched here.
   - crosvm saves the distributor and redistributor as raw dumps of every 32-bit offset and
     restores them by writing every offset back in order
     (`devices/src/irqchip/kvm/aarch64.rs`, `set_dist_regs` / `set_redist_regs`).
   - Reading `GIC*_ICENABLER` returns the enabled set, but KVM's userspace write handler for it is
     write-1-to-clear (`vgic_uaccess_write_cenable` sets `irq->enabled = false` for each set bit,
     `arch/arm64/kvm/vgic/vgic-mmio.c`, v6.17). Same for `ICPENDR` / `ICACTIVER`.
   - `ICENABLER` (0x180) is written right after `ISENABLER` (0x100) with the same value, so the
     restore re-enables then immediately disables every enabled IRQ. Saved data confirms it:
     `GICR_ISENABLER0 = GICR_ICENABLER0 = 0x0800007f` (bit 27 = arch timer PPI),
     `GICD_ISENABLER1 = GICD_ICENABLER1 = 0xf0` (virtio SPIs).
   - Symptom: restored guest sits in `WFI` forever (vCPU thread in `kvm_vcpu_block`, zero user
     time, no console output, no network). Through Cuttlefish this surfaced as OpenWrt being
     unreachable, so `run_cvd` died on `Failed to send network service reset`.
   - Fix: skip the clear banks (frame offsets `0x180..=0x1ff`, `0x280..=0x2ff`, `0x380..=0x3ff`,
     in the distributor and the redistributor SGI frame) on restore. The set banks already carry
     the state. See the patch. This is worth upstreaming to crosvm.

Upstream `fc036d83c` (2026-08, restore pvclock on cold restore) is also included in the build used.

## Building the replacement crosvm (arm64, native, ~1.5 min)

On `arm_desktop` everything lives under `/home/ingots/snaptest` (no sudo, shell profiles untouched):

```sh
export RUSTUP_HOME=/home/ingots/snaptest/rust/rustup CARGO_HOME=/home/ingots/snaptest/rust/cargo
export PATH=$CARGO_HOME/bin:$PATH        # rustup installed with --no-modify-path
git clone https://chromium.googlesource.com/crosvm/crosvm && cd crosvm
git submodule update --init --depth 1
git apply .../snapshot/crosvm-vgic-restore-skip-clear-regs.patch
cargo build --release --no-default-features \
  --features "audio balloon gpu qcow usb net composite-disk"
```

- `--no-default-features` is required: the default `virtio_wl` feature turns Cuttlefish's
  `--wayland-sock` into a guest virtio-wl device, which cannot be snapshotted
  (`virtio_snapshot not implemented for virtio-wl`). Android's own crosvm build leaves it out.
- `composite-disk` is required for Cuttlefish's composite disk images.
- System deps already present on `arm_desktop`: libcap, libdrm, wayland, protoc, clang.
- Every flag the Android 15 `run_cvd` passes to crosvm is still accepted upstream (including the
  deprecated `--cid`, `--sound=<socket>`, `--extended-status`).
- Install by replacing `<runtime_root>/bin/aarch64-linux-musl/crosvm` (`bin/crosvm` is a wrapper
  script that execs `bin/$(uname -m)-linux-musl/crosvm`). The resulting binary is dynamically
  linked, unlike the static musl original.
- **Build it in a `debian:bookworm` container**, not directly on the host. A host build links
  against the host's glibc 2.38+, which fails inside the `cuttlefish-host` Docker image
  (`GLIBC_2.38 not found`). Built in `debian:bookworm-slim` (glibc 2.36) the same binary runs on
  the host and in the image. Build deps: `build-essential clang pkg-config libcap-dev libdrm-dev
  libwayland-dev wayland-protocols protobuf-compiler libssl-dev git` plus rustup (toolchain per
  crosvm's `rust-toolchain`, 1.88.0). The build dir is `/home/ingots/snaptest/crosvm/target-bookworm`.

## Restore constraints (affect cuttle_server design)

- **Restore is pinned to the original `HOME` and instance number.** The snapshot stores the
  original absolute paths, instance number, TAP names and vsock CID (`snapshot_meta_info.json`
  records `HOME` and `"guest_snapshot": {"2": ...}`). Restoring into another `HOME` / instance
  makes `assemble_cvd` try to clean the *original* instance's directories **and the uid-wide
  `/tmp/cf_env_<uid>/`**. It only aborted because an `lsof` check saw other running instances
  using that directory. Any server-side restore must reuse the same runtime dir and
  `instance_num`, and must never point a restore at a different `HOME`.
- Runtime directory paths must stay short. Cuttlefish creates Unix sockets under them and socket
  paths are limited to 108 characters (`/var/lib/cvd/<32 hex>` is fine; a scratch directory under
  a deep home path was not).
- A failed `snapshot_take` can wedge the guest (adb dead, `snapshot_util_cvd` hung in the
  post-resume hook). The server should treat a failed snapshot as fatal for that instance.
- Snapshot size ≈ guest RAM + instance overlays (~4.5 GB at 4 GB RAM). Snapshot creation pauses
  the device for ~3 s. Restoring is repeatable and doesn't modify the snapshot.

## Deployment on arm_desktop

The patched crosvm lives at `/home/ingots/cuttlefish/crosvm/09438a730-vgicfix/` (`crosvm`,
`crosvm.sha256`, the patch, and `BUILD_INFO.txt`). It is installed as
`bin/aarch64-linux-musl/crosvm` in all three challenge7 runtimes (`android-15.0.0_r1`, `_r2`,
`_r4`). Each runtime keeps the original as `bin/aarch64-linux-musl/crosvm.orig`. The three
originals were byte-identical, as were their `run_cvd`s, so one build covers all of them.
Rollback is `mv crosvm.orig crosvm` in each runtime.

The swap was done by atomic rename while instances were running. Running instances keep the old
binary in memory; a guest reboot relaunches crosvm and picks up the new one (checked: the new
binary accepts every flag `run_cvd` passes, and a guest reboot works).

Verified with `snapshot/snapshot_cycle_test.sh` and each runtime's real template kernel, 6 CPUs,
SELinux enforcing (a process and a file survive a snapshot -> kill/overwrite -> restore, with the
same pid):

| Runtime | Kernel | Boot | Snapshot | Restore | Result |
|---|---|---|---|---|---|
| `android-15.0.0_r1` | 7.1.1.a, 6.6.30 | 60 s | 9.2 s, 12 GB | 40 s | PASS |
| `android-15.0.0_r2` (copy) | 7.1.2.a, 6.6.46 | 44 s | 3.5 s, 6.1 GB | 18 s | PASS |
| `android-15.0.0_r4` | 7.1.3.b, 6.6.50 | 60 s | 5.8 s, 12 GB | 37 s | PASS |

(Timings on the live runtimes were taken while production instances were running. Snapshot size
varied between 6 and 12 GB, so budget about 12 GB per snapshot.) Normal launches without any
snapshot flag, including the default vhost-user vsock and an in-guest reboot, also work with the
new crosvm.

## Server and CLI implementation

Implemented in `cuttle_types`, `cuttle_server` and `cuttle_cli`; documented in
`cuttle_server/cuttle_server/README.md` (the "Snapshots" section) and the `cuttle-cli` skill.

- **Template**: `snapshot_supported = true` (host backend, `command_mode = "legacy"`, runtime must
  have `bin/snapshot_util_cvd`; validated at load time).
- **Server config**: `snapshot_root` (default `/var/lib/cuttlefish_snapshots`).
- **Launch**: `cuttle-cli start <template> --snapshots` adds `--snapshot_compatible
  --gpu_mode=guest_swiftshader --vhost_user_vsock=false`.
- **CLI**: `snapshot create <instance> <name>`, `snapshot list [--instance] [--template]`,
  `snapshot show <name>`, `snapshot delete <name>`, `snapshot restore <instance> <name>`.
- **Ownership**: same rules as instances (per-user scope, names unique per owner, admin sees all
  and must use the id for an ambiguous name). A snapshot belongs to the instance's owner.
- **Restore**: allowed for active, crashed, stopped and expired instances. It checks that the
  snapshot is ready, owner/template/backend match, the instance number and runtime directory
  match, and the host tools fingerprint (sha256 of `run_cvd`, `assemble_cvd`,
  `snapshot_util_cvd`, `crosvm`) is unchanged. A running instance is stopped first; a stopped or
  expired one is revived (its slot and name must still be free). The runtime directory is
  recreated from the snapshot (restoring into an empty `HOME` works), app auto-loading is skipped.
- **Data**: a `snapshots` table in the existing sqlite database; snapshot data under
  `snapshot_root/<snapshot_id>`. Deleting refuses paths outside `snapshot_root` and is refused
  while a restore is reading the snapshot. Snapshots interrupted by a server restart are marked
  failed.
- **Docker backend**: rejects snapshot operations with a clear error, and templates cannot enable
  `snapshot_supported` for it.

Tests: 103 server tests and 56 CLI tests (`cd cuttle_server && uv run --project .. python -m
unittest discover -s cuttle_server/tests`, and the same under `cuttle_cli`), plus
`uv run mypy cuttle_server cuttle_cli cuttle_types`. The restore-rule tests were checked by
mutation (removing the host-tools check, the instance-match check or the admin listing each makes
exactly the matching test fail).

End to end, on arm_desktop, with the new code in a **separate test server** (port 6768, instance
numbers 2-3, its own database and directories, challenge7.1.2.a template) and the real CLI:

- `start --snapshots`: 45 s; `snapshot create`: 3.9 s, 6.0 GiB; list/show correct.
- Changing the guest after the snapshot, then `snapshot restore`: 20 s; the file and the killed
  process (same pid) were back.
- `stop` then `snapshot restore` into the stopped instance (runtime dir removed): 19 s; same state.
- Unknown instance/snapshot -> 404, duplicate name -> 400. Another user gets an empty list, 404 on
  show/delete/restore; the admin sees the snapshot.
- Snapshot and instance records survived a server restart; `snapshot delete` removed the data.

## Can the host tools be built without a full Android build?

**Yes.** Since 2024–2025 the Cuttlefish host tools also live in
[`google/android-cuttlefish`](https://github.com/google/android-cuttlefish) under `base/cvd`, with
a standalone Bazel 8 build (`base/cvd/cuttlefish/package/BUILD.bazel`). It produces the full host
set (`run_cvd`, `assemble_cvd`, `launch_cvd`/`cvd`, `secure_env`, `modem_simulator`,
`openwrt_control_server`, `process_restarter`, `snapshot_util_cvd`, ...) plus crosvm itself (built
from a pinned upstream revision via `build_external/crosvm`). This is how the `cuttlefish-base`
Debian package is built (`tools/buildutils/build_packages.sh` installs the build deps, which
needs apt/sudo).

Version matching:

- The Android 15 images in use came with host package build `13263448`, which is newer than the
  `android-15.0.0_r2` source tag. The string `Failed to send network service reset` does not
  exist at that tag. AOSP `device/google/cuttlefish` tags therefore aren't an exact match for the
  host package in use.
- The GitHub host tools track current development. Their compatibility with Android 15 guest
  images is plausible (Cuttlefish aims to launch older branches) but **untested here**.
- **Not needed for snapshots right now:** the existing Android 15 host package works once crosvm
  is replaced. A host-tool rebuild would only matter to change `run_cvd` behaviour, e.g. making
  the OpenWrt network reset non-fatal so restore works without the AP VM.
- The crosvm pinned by android-cuttlefish (`597fa65c6`) still has bug 3, so a host package built
  from there would need the same patch for arm64 restore.
- A full build was not attempted (per instructions). It would need Bazel 8.5.1 and the deps from
  `build_packages.sh`; `arm_desktop` has no passwordless sudo, so `benchmarks` may be the better
  build host.

## Standalone crosvm reproducer

`snapshot/crosvm_openwrt_restore_test.sh` boots the OpenWrt AP image directly under crosvm (no
Cuttlefish, no TAPs). It lets the image's deliberate first-boot reboot finish, starts a
once-a-second `TICK-<uptime>` loop on the console, snapshots, kills, cold-restores into a new
process, and checks for ticks and a RAM-backed marker. Results:

| crosvm | Result after restore |
|---|---|
| Original (host package) | `Kernel panic - not syncing: kernel stack overflow` (bug 1) |
| Upstream `09438a730` | Alive but silent: vCPU blocked in `WFI`, no ticks (bug 3) |
| Upstream + patch | Ticks resume (`TICK-26` → `TICK-28..40`), marker intact |

## State on arm_desktop

- Nothing from the tests is running. The production server's instances (4-31) were not touched,
  and neither were its config, checkout or service.
- Only the three challenge7 runtimes were modified (crosvm swapped; `crosvm.orig` kept).
- `/home/ingots/cuttlefish/crosvm/09438a730-vgicfix/`: the deployed crosvm build.
- `/home/ingots/snaptest/` (~7 GB, scratch, safe to delete): `crosvm` (source and build trees),
  `rust` and `bookworm-cache` (toolchains), `rt-r2` (runtime copy used for tests), `py` (cbor2
  and platformdirs for the test tooling), `owrt` (standalone crosvm test), build logs.

## Next steps

To put this into production on `arm_desktop` (none of this has been done; the production service
is unchanged):

1. Create the snapshot volume: `sudo mkdir -p /var/lib/cuttlefish_snapshots && sudo chown
   ingots: /var/lib/cuttlefish_snapshots` (needs about 12 GB per snapshot; the disk has ~1.5 TB
   free).
2. In `/home/ingots/cuttlefish/server_config/templates/challenge7.*.toml`, add
   `snapshot_supported = true`. Optionally set `snapshot_root` in `cuttle_server.toml`.
3. Deploy this code to `/home/ingots/kernelcveanalysis` (pull the merged change) and restart
   `cuttle-server.service`. Restarting does not stop running Cuttlefish instances, but check for
   users mid-operation first.
4. Update users' `cuttle-cli`. Instances started before the upgrade were not launched with
   `--snapshot_compatible` and cannot be snapshotted; users start new ones with `--snapshots`.

Further work:

- Upstream the crosvm vGIC restore fix.
- Docker backend: restoring into a new instance. Inside a container every instance has the same
  `HOME` and instance number, which removes the path restriction, but the vsock CID is
  host-global (`10000 + instance_num - 1`) and frozen into the snapshot (snapshots need
  `--vhost_user_vsock=false`), so a restored copy must reuse the snapshot's CID and cannot run
  alongside its source. `snapshot_root` would also need mounting at the same path in every
  container. Needs its own experiment.
- Restoring a snapshot into other instances of the same template would need either that Docker
  work or a way to rewrite the paths Cuttlefish bakes into a snapshot.
- Make snapshot creation asynchronous so it does not hold the server lock, and add a per-user
  snapshot limit if disk use becomes a problem.
- Optional: build `run_cvd` from `google/android-cuttlefish` with the OpenWrt network reset made
  non-fatal, to allow restoring without the Wi-Fi access point VM.

## Production test (2026-11-17, arm_desktop, deployed server)

- Through the deployed server and `cuttle-cli`: start with `--snapshots`, create (7 s, 11.9 GiB), restore, list, show,
  delete, per-user name uniqueness and cross-template restore rejection all behave as designed.
- **Bug (fixed in the working tree, not deployed):** restoring with a template kernel (`--kernel_path`) silently threw
  away the guest's disk. After restore the guest rebooted with
  `reboot: Restarting system with command 'dm-verity device corrupted'` (`device-mapper: verity: 7:632: data block
  2354 is corrupted`, a loop-mounted APEX on `/data`), run_cvd's post-resume hook failed (`Can't find service:
  bluetooth_manager`) and the instance went to `crashed`.
  - Cause (Cuttlefish `assemble_cvd`, not crosvm or cuttle_server): restore copies the snapshot's `overlay.img` (the
    qcow2 holding all guest disk writes) and keeps its mtime. With `--kernel_path` it then re-repacks
    `boot_repacked.img`, `vendor_boot_repacked.img` and `super.img`. That makes `os_composite.img` newer than the
    copied overlay, so `DiskBuilder::BuildOverlayIfNecessary` logs `Overlay is out of date` and creates an
    **empty** overlay. The restored RAM then runs on a disk without its writes. The decision is mtime-only
    (`disk_builder.cpp`), and upstream android-cuttlefish has the same logic.
  - It was **not** time dependent: early snapshots also lost their disk. They only looked fine because the guest page
    cache still held everything that was read. With `echo 3 > /proc/sys/vm/drop_caches` after restore, a 25 s
    snapshot crashes the same way. Late snapshots fail by themselves because by then artd/dexopt has evicted APEX
    pages, which are then re-read from the blank disk. The old marker check (`cat` of a small file) read from page
    cache and could not detect this. Default-kernel templates are not affected, because nothing is repacked.
  - Fix: before `launch_cvd --snapshot_path`, `HostCuttlefishBackend.protect_snapshot_overlays` sets the snapshot's
    `instances/cvd-*/*overlay.img` mtime to now + 1 day, so assemble_cvd keeps the overlay. The rebuilt components
    are content-identical (`super.img` and the vbmeta images are byte-identical). Only the boot images and GPT GUIDs
    differ, and the running guest never re-reads those. crosvm resets the mtime to the present on the first write.
  - Verified with the updated `snapshot_cycle_test.sh`, which now also writes 256 MB of random data, deletes it after
    the snapshot, and checks its hash after restore and `drop_caches`. With `SNAPSHOT_DELAY=200`: PASS on
    r4 + 7.1.3.a and r1 + 7.1.1.a. Without the fix, the same check fails on a 25 s snapshot.
  - Minor, not fixed: assemble_cvd also recreates `pstore`, `hwcomposer-pmem` and `access-kregistry` blank on
    restore. No visible effect so far.
- Possible race (seen once): the first restore failed with "Instance directory files in use ... Observed PIDs: <server>"
  because the server was reading the instance's logcat for the `/logs` poll while assemble_cvd ran its lsof check.

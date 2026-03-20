# Pipe Wakeup Race-Extender Primitive

This primitive widens tight race windows by pinning two threads to the same CPU: a low-priority thread enters the vulnerable kernel path, while a higher-priority helper thread blocks on a pipe. Waking the helper preempts the low-priority thread at a controlled moment, which is useful for delayed-free, `kfree_rcu`, and other timing-sensitive races.

## Preconditions

- The target needs a race where briefly pausing one thread at the right point materially increases exploitability.
- You must be able to pin both threads to the same CPU.
- You need a path to wake the blocked helper thread from another thread or process at the right moment.
- The platform must allow enough priority differentiation for the helper to preempt the low-priority path. Real-time priority is ideal, but even `nice` changes can sometimes be enough.

## Usage

1. Call `init_pipe_wakeup_race_extender` with the target CPU and the desired nice values for the low-priority runner and the wakeup helper.
2. Call `execute_pipe_wakeup_race_extender_arm` to start the helper thread and block it on the pipe read.
3. Call `execute_pipe_wakeup_race_extender_prepare_lowprio` from the thread that will enter the vulnerable kernel path.
4. Trigger the kernel path.
5. Call `execute_pipe_wakeup_race_extender_fire` from a third thread when you want the helper to wake and preempt the low-priority runner.
6. Join or reset the helper with `execute_pipe_wakeup_race_extender_wait`.

## Key Concepts

- This primitive does not trigger the race itself. It only creates the scheduler conditions that make the race easier to win.
- The Android CVE-2022-22057 notes use this pattern to let a delayed free complete while another thread is paused mid-cleanup.
- Pipe wakeups are reliable because a blocked `read()` is cheap to arm and fast to wake from another thread.

## How It Works

The helper thread is pinned to the target CPU, assigned a higher priority than the main race thread, and then blocked in a pipe read. The main race thread is pinned to the same CPU with a lower priority and enters the kernel path that needs to be interrupted at a carefully chosen point. A third thread writes one byte to the helper pipe, making the blocked helper runnable immediately.

Because both threads share one CPU and the helper has higher priority, the wakeup forces a preemption. That creates a deterministic pause in the low-priority kernel path, which can be enough for deferred frees, RCU callbacks, or reclaim attempts on other CPUs to complete before execution resumes.

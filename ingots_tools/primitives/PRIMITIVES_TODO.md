- arb read write with overlapped pipe buffer
  - describe actual read process, which fields to write and read
- pipe buffer page spray trick to turn any double free into rw on pipe buffer
- tricks with linear mapping (https://projectzero.google/2025/11/defeating-kaslr-by-doing-nothing-at-all.html), and scan for base trick
  - also maybe mention directly in arb read write thing
  - maybe also mention how to turn arb linear write to arb read (/proc/self/mounts)
- trick from article about unreliable write into reliable write: https://projectzero.google/2025/11/defeating-kaslr-by-doing-nothing-at-all.html (seen this trick several times)
- how to become root and disable selinux with arb read write
- unix socket sendmsg spraying with iovec

# Things which are not needed (not android)

core_info privilege execution
msg_msg

Selinux is made of types, which are like something with permissions.
A process has a domain, which has a type.
A type can be allowed to do things to other types.
The things it can do are permissions and permissions are part of a certain class.
- Some domains can apparently be set to permissive, so denies never actually matter

A type attribute is like a group, a type inherites permissions of the attributes it is in

Possible permission statements:
- allow: allow an action
- allowxperm: allow permissions which take in extra arguments, finer grain for certain syscalls
- neverallow: dont allow even if it is allowed by some other rule
- dontaudit: don't audit in kernel log when an action fails (this rule doesn't enforce anything on its own)
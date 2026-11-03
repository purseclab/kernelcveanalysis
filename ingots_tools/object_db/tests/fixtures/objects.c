typedef unsigned long size_t;
void *kmalloc(size_t size, unsigned int flags);
void *kzalloc(size_t size, unsigned int flags);
struct file { int value; };
typedef const struct file *file_ptr;
struct inner { file_ptr ptr; };
union choice { unsigned long scalar; file_ptr ptr; };
struct many { int f0,f1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11; };
struct outer { struct inner embedded; union choice alternatives; file_ptr array[2]; unsigned int bits:3; void (*callback)(void); };
struct flex { int count; char data[]; };
struct outer *make_outer(void) { return kmalloc(sizeof(struct outer), 0); }
struct many *make_many(void) { return kzalloc(sizeof(struct many), 0); }
struct flex *make_flex(size_t n) { return kmalloc(sizeof(struct flex) + n, 0); }
struct many *make_dynamic(size_t n) { return kmalloc(n, 0); }
#define ALLOC_SIZE sizeof(struct outer)
struct outer *make_macro(void) { return kmalloc(ALLOC_SIZE, 0); }
struct many *make_other(void) { struct many { long other; }; return kmalloc(sizeof(struct many), 0); }
struct anonymous_outer { union { struct { file_ptr anonymous_ptr; }; unsigned long raw; }; };
struct kmem_cache;
struct kmem_cache *kmem_cache_create(const char *name, size_t size, size_t align, unsigned long flags, void (*ctor)(void *));
void *kmem_cache_alloc(struct kmem_cache *cache, unsigned int flags);
struct outer *make_cached(void) {
    struct kmem_cache *cache = kmem_cache_create("outer_cache", sizeof(struct outer), 0, 0, 0);
    return kmem_cache_alloc(cache, 0);
}

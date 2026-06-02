# Kernel KASLR and Mapping Randomization

This note summarizes how Linux randomizes the kernel image, linear/direct
mapping, and vmemmap on `x86_64` and `aarch64`, based on the local kernel tree
at `/home/jack/Documents/college/purdue/research/linux_src/linux`.

## x86_64

### Two Separate Randomization Stages

`x86_64` has two mostly separate KASLR mechanisms:

1. **Kernel image KASLR** in `arch/x86/boot/compressed/kaslr.c`.
2. **Kernel memory region KASLR** in `arch/x86/mm/kaslr.c`.

`CONFIG_RANDOMIZE_BASE` controls image KASLR. `CONFIG_RANDOMIZE_MEMORY`
depends on it and randomizes the base of the direct map, vmalloc, and vmemmap.
`kaslr_memory_enabled()` disables memory-region randomization when KASAN is
enabled.

### Kernel Image KASLR

The decompressor calls `choose_random_location()` from
`arch/x86/boot/compressed/misc.c`.

`choose_random_location()`:

- exits early for `nokaslr`;
- sets `KASLR_FLAG` in `boot_params->hdr.loadflags`;
- chooses a randomized physical destination for the decompressed kernel;
- on `x86_64`, chooses a separate randomized virtual address.

Physical placement is chosen by scanning EFI/E820 usable RAM, excluding unsafe
ranges, and selecting a random `CONFIG_PHYSICAL_ALIGN` slot. The lower bound is:

```c
min_addr = ALIGN(min(current_output, 512MB), CONFIG_PHYSICAL_ALIGN)
```

Virtual placement is chosen by `find_random_virt_addr()`:

```c
slots = 1 + (KERNEL_IMAGE_SIZE - minimum - image_size) / CONFIG_PHYSICAL_ALIGN;
virt_addr = LOAD_PHYSICAL_ADDR + random_slot * CONFIG_PHYSICAL_ALIGN;
```

The Kconfig help describes this as separate physical and virtual
randomization on 64-bit: physical placement can be anywhere suitable in RAM,
while the virtual image offset has roughly a 16MB-to-1GB range.

At runtime:

```c
kaslr_offset() = &_text - __START_KERNEL
```

The early `head64.c` path computes `load_delta` from the actual physical load
address and fixes up `phys_base`.

### Direct Map, vmalloc, and vmemmap KASLR

`kernel_randomize_memory()` in `arch/x86/mm/kaslr.c` randomizes these regions
in fixed order:

```c
page_offset_base
vmalloc_base
vmemmap_base
```

The order is preserved, but gaps before each region are randomized. The initial
search starts at:

- 4-level paging: `__PAGE_OFFSET_BASE_L4 = 0xffff888000000000`
- 5-level paging: `__PAGE_OFFSET_BASE_L5 = 0xff11000000000000`

The upper limit is `CPU_ENTRY_AREA_BASE`, which is below
`__START_KERNEL_map`. Region sizes are computed before placing them:

- direct map size is based on `max_pfn`, rounded to TB units, plus
  `CONFIG_RANDOMIZE_MEMORY_PHYSICAL_PADDING`;
- vmalloc uses `VMALLOC_SIZE_TB`;
- vmemmap size is derived from the direct-map size and `sizeof(struct page)`,
  rounded to TB units.

For each region:

```c
entropy = random_gap & PUD_MASK;
base = current_vaddr + entropy;
current_vaddr = round_up(base + region_size + 1, PUD_SIZE);
```

So these bases are randomized at PUD granularity. On normal 4-level x86_64,
that is 1GB.

If `CONFIG_DYNAMIC_MEMORY_LAYOUT` is not active, the compile-time constants are
used:

- direct map: `__PAGE_OFFSET_BASE_L4`
- vmalloc: `__VMALLOC_BASE_L4 = 0xffffc90000000000`
- vmemmap: `__VMEMMAP_BASE_L4 = 0xffffea0000000000`

With 5-level paging, the corresponding L5 constants are used.

### Address Translation Consequences

`arch/x86/include/asm/page_64.h` uses `phys_base` for kernel image symbols and
`PAGE_OFFSET` / `page_offset_base` for direct-map addresses:

```c
image physical = kernel_va - __START_KERNEL_map + phys_base
direct physical = direct_va - page_offset_base
```

An exploit usually needs separate leaks for:

- image KASLR: `kaslr_base` / `phys_base`;
- direct-map KASLR: `page_offset_base`;
- vmemmap KASLR: `vmemmap_base`.

A text-symbol leak does not determine `page_offset_base` or `vmemmap_base` when
`CONFIG_RANDOMIZE_MEMORY` is active.

## aarch64

### Seed and Early Setup

`aarch64` KASLR is driven by `arch/arm64/kernel/kaslr.c`.
`kaslr_early_init()` reads `/chosen/kaslr-seed` from the FDT, wipes it, checks
for `nokaslr`, optionally mixes architectural random seed entropy, and returns
0 if randomization is disabled or no seed is available.

The arm64 head path calls `kaslr_early_init()` from `head.S`. If a nonzero
offset is returned, the kernel is remapped and later enters `start_kernel()`
from the randomized virtual image address.

### Kernel Image KASLR

The image virtual offset is computed from the seed:

```c
mask = ((1UL << (VA_BITS_MIN - 2)) - 1) & ~(SZ_2M - 1);
offset = BIT(VA_BITS_MIN - 3) + (seed & mask);
```

This places the image in the middle half of the vmalloc area and rounds the
offset to 2MB. `VA_BITS_MIN` is 48 for 52-bit VA kernels so that one kernel
binary can still fall back to 48-bit hardware.

Runtime image translation uses:

```c
kaslr_offset() = kimage_vaddr - KIMAGE_VADDR
kimage_voffset = kimage_vaddr - physical_text_address
image physical = kernel_va - kimage_voffset
```

`kimage_voffset` is saved in `head.S` after the final image mapping is active.

### Linear Map Randomization

The arm64 linear map virtual interval itself is fixed by the VA layout:

```c
PAGE_OFFSET = -(1UL << VA_BITS)
PAGE_END    = -(1UL << (vabits_actual - 1))
```

The randomized part is not the virtual `PAGE_OFFSET`; it is the physical memory
base represented by `PAGE_OFFSET`, stored in `memstart_addr`.

`kaslr_early_init()` stores the top 16 bits of the KASLR seed:

```c
memstart_offset_seed = seed >> 48;
```

Later, `arm64_memblock_init()` computes the span available for sliding the
linear map:

```c
range = linear_region_size - (memblock_end_of_DRAM() - memblock_start_of_DRAM());
```

If there is enough slack:

```c
range /= ARM64_MEMSTART_ALIGN;
memstart_addr -= ARM64_MEMSTART_ALIGN *
                 ((range * memstart_offset_seed) >> 16);
```

So arm64 linear-map randomization changes `PHYS_OFFSET` / `memstart_addr`.
The virtual linear-map range is still `[PAGE_OFFSET, PAGE_END)`.

Linear-map translation is:

```c
linear physical = ((linear_va & ~PAGE_OFFSET) + memstart_addr)
linear virtual  = ((physical - memstart_addr) | PAGE_OFFSET)
```

### vmemmap Behavior

arm64 does not randomize `VMEMMAP_START` the way x86 randomizes
`vmemmap_base`. The virtual vmemmap region is derived from the VA layout:

```c
VMEMMAP_START = -VMEMMAP_SIZE - SZ_2M
VMEMMAP_END   = VMEMMAP_START + VMEMMAP_SIZE
```

However, the sparsemem `vmemmap` pointer used for PFN-to-page calculations is
offset by `memstart_addr`:

```c
vmemmap = (struct page *)VMEMMAP_START - (memstart_addr >> PAGE_SHIFT)
```

That means linear-map randomization also changes the effective `vmemmap`
pointer. A leak of an arbitrary `struct page *` is not enough to recover
`vmemmap` by alignment alone unless the matching PFN or `memstart_addr` is
known.

### Module Region Randomization

arm64 also randomizes `module_alloc_base` unless KASAN constrains it.

If `CONFIG_RANDOMIZE_MODULE_REGION_FULL` is enabled, modules are randomized
over a 2GB window covering the kernel image. Otherwise, the module allocation
base is randomized inside the normal module region while keeping branches to
the core kernel reachable without veneers.

The lower 21 bits of the seed choose the module base:

```c
module_alloc_base += (module_range * (seed & ((1 << 21) - 1))) >> 21;
module_alloc_base &= PAGE_MASK;
```

### Address Translation Consequences

An arm64 exploit should treat these as distinct values:

- `kimage_voffset` / image KASLR offset for kernel text and data;
- `memstart_addr` / `PHYS_OFFSET` for linear-map translation;
- effective `vmemmap` pointer, which depends on `VMEMMAP_START` and
  `memstart_addr`;
- `module_alloc_base` for module-region placement.

A kernel text leak gives the image KASLR offset, but it does not directly give
the randomized linear-map physical offset. A linear-map leak can give
`memstart_addr` if the physical address is known:

```c
memstart_addr = physical - (linear_va & ~PAGE_OFFSET)
```

Given `memstart_addr`, the effective sparsemem base is:

```c
vmemmap = VMEMMAP_START - (memstart_addr >> PAGE_SHIFT)
```

## Quick Comparison

| Region | x86_64 | aarch64 |
| --- | --- | --- |
| Kernel image | Physical and virtual placement randomized separately by compressed boot KASLR. | Virtual image offset chosen in `kaslr_early_init()`, rounded to 2MB. |
| Linear/direct map | `page_offset_base` virtual address is randomized by `CONFIG_RANDOMIZE_MEMORY`. | Virtual `PAGE_OFFSET` is fixed; `memstart_addr` / `PHYS_OFFSET` is randomized. |
| vmemmap | `vmemmap_base` virtual address is randomized directly. | `VMEMMAP_START` is fixed for the VA layout; effective `vmemmap` pointer shifts with `memstart_addr`. |
| vmalloc | `vmalloc_base` is randomized directly. | Image KASLR chooses an offset from the vmalloc-area range; vmalloc region layout itself is fixed by VA layout. |
| Modules | Separate module KASLR behavior; module space is affected by image KASLR range. | `module_alloc_base` is explicitly randomized from the seed. |
| KASAN effect | Disables x86 memory-region KASLR. | Constrains arm64 module placement; image KASLR still has special KASAN handling. |

## Source Map

- `arch/x86/boot/compressed/kaslr.c`: x86 image physical/virtual selection.
- `arch/x86/boot/compressed/misc.c`: calls `choose_random_location()`.
- `arch/x86/mm/kaslr.c`: x86 direct-map/vmalloc/vmemmap randomization.
- `arch/x86/include/asm/page_64.h`: x86 image/direct-map physical translation.
- `arch/x86/include/asm/page_64_types.h`: x86 direct-map and image constants.
- `arch/x86/include/asm/pgtable_64_types.h`: x86 vmalloc/vmemmap constants.
- `arch/arm64/kernel/kaslr.c`: arm64 seed parsing, image offset, module base,
  and `memstart_offset_seed`.
- `arch/arm64/kernel/head.S`: arm64 KASLR remap path and `kimage_voffset`.
- `arch/arm64/mm/init.c`: arm64 `memstart_addr` and linear-map randomization.
- `arch/arm64/include/asm/memory.h`: arm64 image, linear-map, and vmemmap
  translation macros.
- `arch/arm64/include/asm/pgtable.h`: arm64 effective `vmemmap` pointer.

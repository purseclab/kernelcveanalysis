from pathlib import Path
import tempfile

from elftools.elf.elffile import ELFFile

from .adb import upload_file, upload_tools, expand_binary as adb_expand_binary

def expand_binary(binary_path: Path, expand_path: Path):
    upload_tools()

    elf = ELFFile.load_from_path(binary_path)

    # only 64 bit aarch 64 for now
    assert (elf['e_ident']['EI_CLASS'], elf['e_machine']) == ('ELFCLASS64', 'EM_AARCH64')

    entry = elf.header['e_entry']
    entry_file_offset = None

    for segment in elf.iter_segments():
        if segment.header['p_type'] != 'PT_LOAD':
            continue

        vaddr = segment.header['p_vaddr']
        vsize = segment.header['p_memsz']
        file_offset = segment.header['p_offset']
        if vaddr <= entry and entry < (vaddr + vsize):
            entry_file_offset = file_offset + (entry - vaddr)
    
    assert entry_file_offset is not None, 'could not find file offset of entrypoint'

    with open(binary_path, 'rb') as f:
        binary_data = f.read()
    
    loop_instruction = b'\x00\x00\x00\x14'
    original_instr = binary_data[entry_file_offset:entry_file_offset+len(loop_instruction)]

    modified_binary = binary_data[:entry_file_offset] + loop_instruction + binary_data[entry_file_offset+len(loop_instruction):]
    binary_dst = '/data/local/tmp/expand_binary'

    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(modified_binary)
        tmp.flush()
        upload_file(Path(tmp.name), Path(binary_dst), executable=True)
    
    expand_result = adb_expand_binary(binary_dst)
    changed_offset = entry - expand_result.load_addr
    expand_binary = expand_result.expanded_binary[:changed_offset] + original_instr + expand_result.expanded_binary[changed_offset+len(original_instr):]
    
    with open(expand_path, 'wb') as f:
        f.write(expand_binary)
    
    print(f'loaded at: {hex(expand_result.load_addr)}')
    print(f'entry point at: {hex(entry)}')


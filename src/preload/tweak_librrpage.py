#!/usr/bin/env python3
# This script adjusts librrpage.so to have the final layout that we want
# See rr_page.S for a description of the expected final layout of librrpage

import struct
import os
import sys

# How much space (and where) we reserved in the middle of the file for
# the section header
new_table_offset = 0x1000
reserved_size = 0x1000

# Force this alignment for any sections
sect_align = 0x10

# some constants
ELFCLASS32 = 1
ELFCLASS64 = 2

def read_byte(f):
	return struct.unpack('b', f.read(1))[0]

def read_uint64(f):
	return struct.unpack('Q', f.read(8))[0]

def write_uint64(f, v):
	return f.write(struct.pack('Q', v))

def read_uint32(f):
	return struct.unpack('I', f.read(4))[0]

def write_uint32(f, v):
	return f.write(struct.pack('I', v))

def read_uint16(f):
	return struct.unpack('H', f.read(2))[0]

def seek_nth_section_sh_offset(f, shtable, e_shentsize, n, offset):
	f.seek(shtable + n*e_shentsize + offset)

def read_uptr(is64, f):
	if is64:
		return read_uint64(f)
	else:
		return read_uint32(f)

def write_uptr(is64, f, v):
	if is64:
		return write_uint64(f, v)
	else:
		return write_uint32(f, v)

with open(sys.argv[1], 'rb+') as f:
	assert f.read(4) == b'\x7fELF'
	elfclass = read_byte(f)
	assert (elfclass == ELFCLASS32) or (elfclass == ELFCLASS64)
	is64 = elfclass == ELFCLASS64

	# Hardcoded offsets for fields of the ELF header - a more sophisticated
	# tweaker would parse the structure, but we only need to make some very
	# small tweaks
	if is64:
		e_shoff_offset = 0x28
		e_shentsize_offset = 0x3a
		e_shnum_offset = 0x3c
		# offset of sh_offset  the section header
		sh_offset_offset = 0x18
	else:
		e_shoff_offset = 0x20
		e_shentsize_offset = 0x2e
		e_shnum_offset = 0x30
		sh_offset_offset = 0x10

	f.seek(e_shoff_offset)
	e_shoff = read_uptr(is64, f)

	f.seek(e_shentsize_offset)
	e_shentsize = read_uint16(f)

	f.seek(e_shnum_offset)
	e_shnum = read_uint16(f)

	old_offset = e_shoff
	size = e_shentsize * e_shnum

	assert size <= reserved_size
	assert old_offset + size == os.stat(sys.argv[1]).st_size

	f.seek(old_offset)
	data = f.read(size)

	f.seek(new_table_offset)
	f.write(data)

	f.seek(e_shoff_offset)
	write_uptr(is64, f, new_table_offset)

	alloc_offset = new_table_offset + size
	for n in range(12, 15):
		seek_nth_section_sh_offset(f, new_table_offset, e_shentsize, n, sh_offset_offset)
		sh_offs = read_uptr(is64, f)
		sh_size = read_uptr(is64, f)

		f.seek(sh_offs)
		sh_data = f.read(sh_size)

		new_section_offset = (alloc_offset + sect_align - 1) & ~(sect_align-1)
		f.seek(new_section_offset)

		f.write(sh_data)

		seek_nth_section_sh_offset(f, new_table_offset, e_shentsize, n, sh_offset_offset)
		write_uptr(is64, f, new_section_offset)

		alloc_offset = new_section_offset + sh_size
		assert (alloc_offset - new_section_offset) <= reserved_size

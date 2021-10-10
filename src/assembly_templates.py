from io import StringIO
import sys

class RawBytes(object):
    """A sequence of literal bytes to appear in an assembly language template."""
    def __init__(self, *bytes):
        self.bytes = bytes

    def __len__(self):
        return len(self.bytes)

class Field(object):
    """A variable field of bytes."""
    def __init__(self, name, byte_length):
        self.name = name
        self.byte_length = byte_length

    def __len__(self):
        return self.byte_length

    def c_type(self):
        types = { 8: 'uint64_t', 4: 'uint32_t', 2: 'uint16_t', 1: 'uint8_t' }
        return types[self.byte_length]

class ShiftField(object):
    """A field embedded at some bit shift offset in another object."""
    def __init__(self, parent, shift, name, byte_length):
        self.parent = parent
        self.shift = shift
        self.name = name
        self.byte_length = byte_length

    def __len__(self):
        return len(self.parent)

    def c_type(self):
        types = { 8: 'uint64_t', 4: 'uint32_t', 2: 'uint16_t', 1: 'uint8_t' }
        return types[self.byte_length]

    def patch_c_type(self):
        types = { 8: 'uint64_t', 4: 'uint32_t', 2: 'uint16_t', 1: 'uint8_t' }
        return types[len(self.parent)]

class AssemblyTemplate(object):
    """A sequence of RawBytes and Field objects, which can be used to verify
    that a given sequence of assembly instructions matches the RawBytes while
    pulling out the Field values for inspection.  Or for creating custom
    assembly stubs, filling out Fields with runtime-determined values."""
    def __init__(self, *chunks):
        # Merge consecutive RawBytes elements together for efficiency of
        # matching and for simplicity of template expansion.
        merged_chunks = []
        current_raw_bytes = []
        for c in chunks:
            if isinstance(c, Field) or isinstance(c, ShiftField):
                # Push any raw bytes before this.
                if current_raw_bytes:
                    merged_chunks.append(RawBytes(*current_raw_bytes))
                    current_raw_bytes = []
                merged_chunks.append(c)
            else:
                current_raw_bytes.extend(c.bytes)
        # Merge in trailing raw bytes.
        if current_raw_bytes:
            merged_chunks.append(RawBytes(*current_raw_bytes))
        self.chunks = merged_chunks

    def fields(self):
        return [c for c in self.chunks if (isinstance(c, Field) or isinstance(c, ShiftField))]

    def bytes(self):
        bytes = []
        for c in self.chunks:
            if isinstance(c, Field):
                bytes.extend([0] * len(c))
            elif isinstance(c, ShiftField):
                bytes.extend(c.parent.bytes)
            else:
                bytes.extend(c.bytes)
        return bytes

templates = {
    'X86SysenterVsyscallSyscallHook': AssemblyTemplate(
        RawBytes(0xe9),         # jmp $syscall_hook_trampoline
        Field('syscall_hook_trampoline', 4),
    ),
    'X86SyscallStubExtendedJump': AssemblyTemplate(
        # This code must match the stubs in syscall_hook.S.
        RawBytes(0x89, 0x25, 0x08, 0x10, 0x00, 0x70), # movl %esp,(stub_scratch_1)
        RawBytes(0xFF, 0x05, 0x0c, 0x10, 0x00, 0x70), # incl (alt_stack_nesting_level)
        RawBytes(0x83, 0x3c, 0x25, 0x0c, 0x10, 0x00, 0x70, 0x01), # cmpl 1,(alt_stack_nesting_level)
        RawBytes(0x75, 0x06),                                     # jne dont_switch
        RawBytes(0x8b, 0x25, 0x00, 0x10, 0x00, 0x70), # movl (syscallbuf_stub_alt_stack),%esp
        # dont_switch:
        RawBytes(0xff, 0x35, 0x08, 0x10, 0x00, 0x70), # pushl (stub_scratch_1)
        RawBytes(0x68),                               # pushl $return_addr
        Field('return_addr', 4),
        RawBytes(0xe9),                               # jmp $trampoline_relative_addr
        Field('trampoline_relative_addr', 4)
    ),
    'X86SyscallStubRestore': AssemblyTemplate(
        RawBytes(0xe9),                               # jmp $trampoline_relative_addr
        Field('trampoline_relative_addr', 4)
    ),
    'X64CallMonkeypatch': AssemblyTemplate(
        RawBytes(0xe8),         # call $relative_addr
        Field('relative_addr', 4),
    ),
    'X64JumpMonkeypatch': AssemblyTemplate(
        RawBytes(0xe9),         # jmp $relative_addr
        Field('relative_addr', 4),
    ),
    'X64SyscallStubExtendedJump': AssemblyTemplate(
        # This code must match the stubs in syscall_hook.S.
        RawBytes(0x48, 0x89, 0x24, 0x25, 0x10, 0x10, 0x00, 0x70), # movq %rsp,(stub_scratch_1)
        RawBytes(0xFF, 0x04, 0x25, 0x18, 0x10, 0x00, 0x70),       # incl (alt_stack_nesting_level)
        RawBytes(0x83, 0x3c, 0x25, 0x18, 0x10, 0x00, 0x70, 0x01), # cmpl 1,(alt_stack_nesting_level)
        RawBytes(0x75, 0x0a),                                     # jne dont_switch
        RawBytes(0x48, 0x8b, 0x24, 0x25, 0x00, 0x10, 0x00, 0x70), # movq (syscallbuf_stub_alt_stack),%rsp
        RawBytes(0xeb, 0x07),                                     # jmp after_adjust
        # dont_switch:
        RawBytes(0x48, 0x81, 0xec, 0x00, 0x01, 0x00, 0x00), # subq $256, %rsp
        # after adjust
        RawBytes(0xff, 0x34, 0x25, 0x10, 0x10, 0x00, 0x70), # pushq (stub_scratch_1)
        RawBytes(0x50),                                     # pushq rax
        RawBytes(0xc7, 0x04, 0x24),                         # movl $return_addr_lo,(%rsp)
        Field('return_addr_lo', 4),
        RawBytes(0xc7, 0x44, 0x24, 0x04),                   # movl $return_addr_hi,(%rsp+4)
        Field('return_addr_hi', 4),
        RawBytes(0xff, 0x25, 0x00, 0x00, 0x00, 0x00),       # jmp *0(%rip)
        Field('jump_target', 8),
    ),
    'X64SyscallStubRestore': AssemblyTemplate(
        RawBytes(0xff, 0x25, 0x00, 0x00, 0x00, 0x00),       # jmp *0(%rip)
        Field('return_addr', 8),
    ),
    'X64DLRuntimeResolve': AssemblyTemplate(
        RawBytes(0x53),                   # push %rbx
        RawBytes(0x48, 0x89, 0xe3),       # mov %rsp,%rbx
        RawBytes(0x48, 0x83, 0xe4, 0xf0), # and $0xfffffffffffffff0,%rsp
    ),
    'X64DLRuntimeResolve2': AssemblyTemplate(
        RawBytes(0x53),                   # push %rbx
        RawBytes(0x48, 0x89, 0xe3),       # mov %rsp,%rbx
        RawBytes(0x48, 0x83, 0xe4, 0xc0), # and $0xffffffffffffffc0,%rsp
    ),
    'X64DLRuntimeResolvePrelude': AssemblyTemplate(
        RawBytes(0xd9, 0x74, 0x24, 0xe0),                               # fstenv -32(%rsp)
        RawBytes(0x48, 0xc7, 0x44, 0x24, 0xf4, 0x00, 0x00, 0x00, 0x00), # movq $0,-12(%rsp)
        RawBytes(0xd9, 0x64, 0x24, 0xe0),                               # fldenv -32(%rsp)
        RawBytes(0x48, 0x87, 0x1c, 0x24), # xchg (%rsp),%rbx
        # r11 is destroyed anyways by _dl_runtime_resolve, so we can use it here.
        RawBytes(0x49, 0x89, 0xdb),       # mov %rbx,%r11
        RawBytes(0x48, 0x89, 0xe3),       # mov %rsp,%rbx
        RawBytes(0x48, 0x83, 0xe4, 0xc0), # and $0xffffffffffffffc0,%rsp
        RawBytes(0x41, 0x53),             # push %r11
        RawBytes(0xc3),                   # ret
    ),
    'X64EndBr': AssemblyTemplate(
        RawBytes(0xf3, 0x0f, 0x1e, 0xfa)
    ),
    'X86EndBr': AssemblyTemplate(
        RawBytes(0xf3, 0x0f, 0x1e, 0xfb)
    ),
    'X64VSyscallEntry': AssemblyTemplate(
        RawBytes(0x48, 0xc7, 0xc0), # movq $[addr], %rax
        Field('addr', 4),
        RawBytes(0xff, 0xd0) # callq *%rax
    ),
    'X64VSyscallReplacement': AssemblyTemplate(
        RawBytes(0x48, 0xc7, 0xc0), # movq $[syscallno], %rax
        Field('syscallno', 4),
        RawBytes(0x0f, 0x05) # syscall
    ),
}

def byte_array_name(name):
    return '%s_bytes' % name

def generate_match_method(byte_array, template):
    s = StringIO()
    fields = template.fields()
    field_types = [f.c_type() for f in fields]
    field_names = [f.name for f in fields]
    args = ', ' + ', '.join("%s* %s" % (t, n) for t, n in zip(field_types, field_names)) \
           if fields else ''

    s.write('  static bool match(const uint8_t* buffer %s) {\n' % (args,))
    offset = 0
    for chunk in template.chunks:
        if isinstance(chunk, Field):
            field_name = chunk.name
            s.write('    memcpy(%s, &buffer[%d], sizeof(*%s));\n'
                    % (field_name, offset, field_name))
        elif isinstance(chunk, ShiftField):
            s.write('    (void)%s;' % chunk.name)
            s.write('    assert(0 && "Matching not implemented for ShiftField");')
        else:
            s.write('    if (memcmp(&buffer[%d], &%s[%d], %d) != 0) { return false; }\n'
                    % (offset, byte_array, offset, len(chunk)))
        offset += len(chunk)
    s.write('    return true;\n')
    s.write('  }')
    return s.getvalue()

def generate_substitute_chunk(s, chunk, byte_array, offset):
    if isinstance(chunk, Field):
        field_name = chunk.name
        s.write('    memcpy(&buffer[%d], &%s, sizeof(%s));\n'
                % (offset, field_name, field_name))
    elif isinstance(chunk, ShiftField):
        generate_substitute_chunk(s, chunk.parent, byte_array, offset);
        typ = chunk.patch_c_type()
        field_name = chunk.name
        s.write('    *((%s*)&buffer[%d]) |= (((%s)%s)<<%d);\n'
                % (typ, offset, typ, field_name, chunk.shift))
    else:
        s.write('    memcpy(&buffer[%d], &%s[%d], %d);\n'
                % (offset, byte_array, offset, len(chunk)))
    offset += len(chunk)
    return offset

def generate_substitute_method(byte_array, template):
    s = StringIO()
    fields = template.fields()
    field_types = [f.c_type() for f in fields]
    field_names = [f.name for f in fields]
    args = ', ' + ', '.join("%s %s" % (t, n) for t, n in zip(field_types, field_names)) \
           if fields else ''

    s.write('  static void substitute(uint8_t* buffer %s) {\n' % (args,))
    offset = 0
    for chunk in template.chunks:
        offset = generate_substitute_chunk(s, chunk, byte_array, offset)
    s.write('  }')
    return s.getvalue()

def generate_field_end_methods(byte_array, template):
    s = StringIO()
    offset = 0
    for chunk in template.chunks:
        offset += len(chunk)
        if isinstance(chunk, Field):
            s.write('  static const size_t %s_end = %d;\n' % (chunk.name, offset))
    return s.getvalue()

def generate_size_member(byte_array):
    s = StringIO()
    s.write('  static const size_t size = sizeof(%s);' % byte_array)
    return s.getvalue()

def generate(f):
    # Raw bytes.
    for name, template in templates.items():
        bytes = template.bytes()
        f.write('static const uint8_t %s[] = { %s };\n'
                % (byte_array_name(name), ', '.join(['0x%x' % b for b in bytes])))
    f.write('\n')

    # Objects representing assembly templates.
    for name, template in templates.items():
        byte_array = byte_array_name(name)
        f.write("""class %(class_name)s {
public:
%(match_method)s

%(substitute_method)s

%(field_end_methods)s
%(size_member)s
};
""" % { 'class_name': name,
        'match_method': generate_match_method(byte_array, template),
        'substitute_method': generate_substitute_method(byte_array, template),
        'field_end_methods': generate_field_end_methods(byte_array, template),
        'size_member': generate_size_member(byte_array), })
        f.write('\n\n')

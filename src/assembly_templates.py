import StringIO
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
            if isinstance(c, Field):
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
        return [c for c in self.chunks if isinstance(c, Field)]

    def bytes(self):
        bytes = []
        for c in self.chunks:
            if isinstance(c, Field):
                bytes.extend([0] * len(c))
            else:
                bytes.extend(c.bytes)
        return bytes

templates = {
    'X86VsyscallImplementation': AssemblyTemplate(
        RawBytes(0x51),         # push %ecx
        RawBytes(0x52),         # push %edx
        RawBytes(0x55),         # push %ebp
        RawBytes(0x89, 0xe5),   # mov %esp, %ebp
        RawBytes(0x0f, 0x34),   # sysenter
        RawBytes(0x90),         # nop
        RawBytes(0x90),         # nop
        RawBytes(0x90),         # nop
        RawBytes(0x90),         # nop
        RawBytes(0x90),         # nop
        RawBytes(0x90),         # nop
        RawBytes(0x90),         # nop
        RawBytes(0xcd, 0x80),   # int $0x80
        RawBytes(0x5d),         # pop %ebp
        RawBytes(0x5a),         # pop %edx
        RawBytes(0x59),         # pop %ecx
        RawBytes(0xc3),         # ret
    ),
    'X86VsyscallMonkeypatch': AssemblyTemplate(
        RawBytes(0x50),         # push %eax
        RawBytes(0xb8),         # mov $_vsyscall_hook_trampoline, %eax
        Field('vsyscall_hook_trampoline', 4),
        RawBytes(0xff, 0xe0),   # jmp *%eax
    ),
    'X64VsyscallMonkeypatch': AssemblyTemplate(
        RawBytes(0xb8),         # mov $syscall_number, %eax
        Field('syscall_number', 4),
        RawBytes(0x0f, 0x05),   # syscall
        RawBytes(0xc3),         # ret
    ),
    'X64VsyscallSyscallbufMonkeypatch': AssemblyTemplate(
        RawBytes(0xb8),         # mov $syscall_number, %eax
        Field('syscall_number', 4),
        RawBytes(0xff, 0x25, 0x00, 0x00, 0x00, 0x00),         # jmpq *trampoline_address(%rip)
        Field('trampoline_address', 8),
    ),
}

def byte_array_name(name):
    return '%s_bytes' % name

def generate_match_method(byte_array, template):
    s = StringIO.StringIO()
    fields = template.fields()
    field_types = [f.c_type() for f in fields]
    field_names = [f.name for f in fields]
    args = ', ' + ', '.join("%s* %s" % (t, n) for t, n in zip(field_types, field_names)) \
           if fields else ''
    
    s.write('static bool match(const uint8_t* buffer %s) {\n' % (args,))
    offset = 0
    for chunk in template.chunks:
        if isinstance(chunk, Field):
            field_name = chunk.name
            s.write('    memcpy(%s, &buffer[%d], sizeof(*%s));\n'
                    % (field_name, offset, field_name))
        else:
            s.write('    if (memcmp(&buffer[%d], &%s[%d], %d) != 0) { return false; }\n'
                    % (offset, byte_array, offset, len(chunk)))
        offset += len(chunk)
    s.write('    return true;\n')
    s.write('  }')
    return s.getvalue()

def generate_substitute_method(byte_array, template):
    s = StringIO.StringIO()
    fields = template.fields()
    field_types = [f.c_type() for f in fields]
    field_names = [f.name for f in fields]
    args = ', ' + ', '.join("%s %s" % (t, n) for t, n in zip(field_types, field_names)) \
           if fields else ''
    
    s.write('static void substitute(uint8_t* buffer %s) {\n' % (args,))
    offset = 0
    for chunk in template.chunks:
        if isinstance(chunk, Field):
            field_name = chunk.name
            s.write('    memcpy(&buffer[%d], &%s, sizeof(%s));\n'
                    % (offset, field_name, field_name))
        else:
            s.write('    memcpy(&buffer[%d], &%s[%d], %d);\n'
                    % (offset, byte_array, offset, len(chunk)))
        offset += len(chunk)
    s.write('  }')
    return s.getvalue()

def generate_size_member(byte_array):
    s = StringIO.StringIO()
    s.write('static const size_t size = sizeof(%s);' % byte_array)
    return s.getvalue()

def generate(f):
    # Raw bytes.
    for name, template in templates.iteritems():
        bytes = template.bytes()
        f.write('static const uint8_t %s[] = { %s };\n'
                % (byte_array_name(name), ', '.join(['0x%x' % b for b in bytes])))
    f.write('\n')

    # Objects representing assembly templates.
    for name, template in templates.iteritems():
        byte_array = byte_array_name(name)
        f.write("""class %(class_name)s {
public:
  %(match_method)s

  %(substitute_method)s

  %(size_member)s
};
""" % { 'class_name': name,
        'match_method': generate_match_method(byte_array, template),
        'substitute_method': generate_substitute_method(byte_array, template),
        'size_member': generate_size_member(byte_array), })
        f.write('\n\n')

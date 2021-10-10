#!/usr/bin/env python3

import assembly_templates
from io import StringIO
import os
import string
import sys
import syscalls

def arch_syscall_number(arch, syscall):
    s = getattr(syscall[1], arch)
    if s == None:
        s = -1
    return s

def write_syscall_enum(f, arch):
    f.write("enum Syscalls {\n")
    undefined_syscall = -1
    for name, obj in sorted(syscalls.all(), key=lambda x: arch_syscall_number(arch, x)):
        syscall_number = getattr(obj, arch)
        if syscall_number is not None:
            enum_number = syscall_number
        else:
            enum_number = undefined_syscall
            undefined_syscall -= 1
        f.write("  %s = %d,\n" % (name, enum_number))
    f.write("  SYSCALL_COUNT,\n")
    f.write("};\n")
    f.write("\n")

def write_syscall_enum_for_tests(f, arch):
    f.write("enum Syscalls {\n")
    undefined_syscall = -1
    for name, obj in sorted(syscalls.all(), key=lambda x: arch_syscall_number(arch, x)):
        syscall_number = getattr(obj, arch)
        if syscall_number is not None:
            enum_number = syscall_number
        else:
            enum_number = undefined_syscall
            undefined_syscall -= 1
        f.write("  RR_%s = %d,\n" % (name, enum_number))
    f.write("};\n")
    f.write("\n")

def write_syscallname_arch(f):
    f.write("template <typename Arch> static std::string syscallname_arch(int syscall);\n")
    f.write("\n");
    for specializer, arch in [("X86Arch", "x86"), ("X64Arch", "x64"), ("ARM64Arch", "generic")]:
        f.write("template <> std::string syscallname_arch<%s>(int syscall) {\n" % specializer)
        f.write("  switch (syscall) {\n");
        def write_case(name):
            f.write("    case %(specializer)s::%(syscall)s: return \"%(syscall)s\";\n"
                    % { 'specializer': specializer, 'syscall': name })
        for name, _ in syscalls.for_arch(arch):
            write_case(name)
        f.write("    default: {")
        f.write("      char buf[100];")
        f.write("      sprintf(buf, \"<unknown-syscall-%d>\", syscall);")
        f.write("      return buf;\n")
        f.write("    }\n")
        f.write("  }\n")
        f.write("}\n")
        f.write("\n")

def write_syscall_record_cases(f):
    def write_recorder_for_arg(syscall, arg):
        arg_descriptor = getattr(syscall, 'arg' + str(arg), None)
        if isinstance(arg_descriptor, str):
            f.write("    syscall_state.reg_parameter<%s>(%d);\n"
                    % (arg_descriptor, arg))
    for name, obj in syscalls.all():
        # Irregular syscalls will be handled by hand-written code elsewhere.
        if isinstance(obj, syscalls.RegularSyscall):
            f.write("  case Arch::%s:\n" % name)
            for arg in range(1,6):
                write_recorder_for_arg(obj, arg)
            f.write("    return PREVENT_SWITCH;\n")

has_syscall = string.Template("""inline bool
has_${syscall}_syscall(SupportedArch arch) {
  switch (arch) {
    case x86:
      return X86Arch::${syscall} >= 0;
    case x86_64:
      return X64Arch::${syscall} >= 0;
    case aarch64:
      return ARM64Arch::${syscall} >= 0;
    default:
      DEBUG_ASSERT(0 && "unsupported architecture");
      return false;
  }
}
""")

is_syscall = string.Template("""inline bool
is_${syscall}_syscall(int syscallno, SupportedArch arch) {
  switch (arch) {
    case x86:
      return syscallno >= 0 && syscallno == X86Arch::${syscall};
    case x86_64:
      return syscallno >= 0 && syscallno == X64Arch::${syscall};
    case aarch64:
      return syscallno >= 0 && syscallno == ARM64Arch::${syscall};
    default:
      DEBUG_ASSERT(0 && "unsupported architecture");
      return false;
  }
}
""")

syscall_number = string.Template("""inline int
syscall_number_for_${syscall}(SupportedArch arch) {
  switch (arch) {
    case x86:
      DEBUG_ASSERT(X86Arch::${syscall} >= 0);
      return X86Arch::${syscall};
    case x86_64:
      DEBUG_ASSERT(X64Arch::${syscall} >= 0);
      return X64Arch::${syscall};
    case aarch64:
      DEBUG_ASSERT(ARM64Arch::${syscall} >= 0);
      return ARM64Arch::${syscall};
    default:
      DEBUG_ASSERT(0 && "unsupported architecture");
      return -1;
  }
}
""")

def write_syscall_helper_functions(f):
    def write_helpers(syscall):
        subs = { 'syscall': syscall }
        f.write(has_syscall.safe_substitute(subs))
        f.write(is_syscall.safe_substitute(subs))
        f.write(syscall_number.safe_substitute(subs))

    for name, obj in syscalls.all():
        write_helpers(name)

def write_check_syscall_numbers(f):
    for name, obj in syscalls.all():
        # XXX hard-coded to x86 currently
        if not obj.x86:
            continue
        f.write("""static_assert(X86Arch::%s == SYS_%s, "Incorrect syscall number for %s");\n"""
                % (name, name, name))

generators_for = {
    'AssemblyTemplates': lambda f: assembly_templates.generate(f),
    'CheckSyscallNumbers': write_check_syscall_numbers,
    'SyscallEnumsX86': lambda f: write_syscall_enum(f, 'x86'),
    'SyscallEnumsX64': lambda f: write_syscall_enum(f, 'x64'),
    'SyscallEnumsGeneric': lambda f: write_syscall_enum(f, 'generic'),
    'SyscallEnumsForTestsX86': lambda f: write_syscall_enum_for_tests(f, 'x86'),
    'SyscallEnumsForTestsX64': lambda f: write_syscall_enum_for_tests(f, 'x64'),
    'SyscallEnumsForTestsGeneric': lambda f: write_syscall_enum_for_tests(f, 'generic'),
    'SyscallnameArch': write_syscallname_arch,
    'SyscallRecordCase': write_syscall_record_cases,
    'SyscallHelperFunctions': write_syscall_helper_functions,
}

def main(argv):
    filename = argv[0]
    base, extension = os.path.splitext(os.path.basename(filename))

    if os.access(filename, os.F_OK):
        with open(filename, 'r') as f:
            before = f.read()
    else:
        before = ""

    stream = StringIO()
    generators_for[base](stream)
    after = stream.getvalue()
    stream.close()

    if before != after:
        with open(filename, 'w') as f:
            f.write(after)

if __name__ == '__main__':
    main(sys.argv[1:])

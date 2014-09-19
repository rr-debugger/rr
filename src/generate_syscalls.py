#!/usr/bin/env python

import os
import string
import sys
import syscalls

def write_syscall_enum(f, arch):
    f.write("enum Syscalls {\n")
    undefined_syscall = -1
    for name, obj in sorted(syscalls.all(), key=lambda x: getattr(x[1], arch)):
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

def write_is_always_emulated_syscall(f):
    semantics_to_retval = { syscalls.ReplaySemantics.EMU: 'true',
                            syscalls.ReplaySemantics.EXEC: 'false',
                            syscalls.ReplaySemantics.EXEC_RET_EMU: 'false',
                            syscalls.ReplaySemantics.MAY_EXEC: 'false' }

    f.write("bool is_always_emulated_syscall(int syscallno) {\n")
    f.write("  switch (syscallno) {\n")
    for name, obj in syscalls.all():
        f.write("    case X86Arch::%s: return %s;\n"
                % (name, semantics_to_retval[obj.semantics]))
    f.write("    default:\n")
    f.write("      FATAL() << \"Unknown syscall \" << syscallno;\n")
    f.write("      return true;\n")
    f.write("  }\n")
    f.write("}\n")
    f.write("\n")

def write_syscallname_arch(f):
    f.write("template <typename Arch> static const char* syscallname_arch(int syscall) {\n")
    f.write("  switch (syscall) {\n");
    def write_case(name):
        f.write("    case Arch::%(syscall)s: return \"%(syscall)s\";\n" % { 'syscall': name })
    for name, obj in syscalls.all():
        write_case(name)
    f.write("    default: return \"<unknown-syscall>\";\n")
    f.write("  }\n")
    f.write("}\n")
    f.write("\n")
        
def write_syscall_record_cases(f):
    def write_recorder_for_arg(syscall, arg):
        arg_descriptor = getattr(syscall, arg, None)
        if arg_descriptor is None:
            return
        if isinstance(arg_descriptor, str):
            f.write("    t->record_remote((void*)t->regs().%s(), sizeof(%s));\n"
                    % (arg, arg_descriptor))
        elif isinstance(arg_descriptor, syscalls.DynamicSize):
            f.write("    t->record_remote((void*)t->regs().%s(), %s);\n"
                    % (arg, arg_descriptor.size_expr))
        elif isinstance(arg_descriptor, syscalls.NullTerminatedString):
            f.write("    t->record_remote_str((void*)t->regs().%s());\n" % arg)
        else:
            # Not reached
            assert None
    for name, obj in syscalls.all():
        # Irregular syscalls will be handled by hand-written code elsewhere.
        if isinstance(obj, syscalls.RegularSyscall):
            f.write("  case Arch::%s:\n" % name)
            for arg in syscalls.RegularSyscall.ARGUMENT_SLOTS:
                write_recorder_for_arg(obj, arg)
            f.write("    break;\n")

has_syscall = string.Template("""inline bool
has_${syscall}_syscall(SupportedArch arch) {
  switch (arch) {
    case x86:
      return X86Arch::${syscall} >= 0;
    case x86_64:
      return X64Arch::${syscall} >= 0;
    default:
      assert(0 && "unsupported architecture");
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
    default:
      assert(0 && "unsupported architecture");
 }
}
""")

syscall_number = string.Template("""inline int
syscall_number_for_${syscall}(SupportedArch arch) {
  switch (arch) {
    case x86:
      assert(X86Arch::${syscall} >= 0);
      return X86Arch::${syscall};
    case x86_64:
      assert(X64Arch::${syscall} >= 0);
      return X64Arch::${syscall};
    default:
      assert(0 && "unsupported architecture");
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

def write_syscall_defs_table(f):
    f.write("static struct syscall_def syscall_defs[] = {\n")
    for name, obj in syscalls.all():
        if isinstance(obj, syscalls.RegularSyscall):
            recorded_args = [arg for arg in syscalls.RegularSyscall.ARGUMENT_SLOTS
                             if getattr(obj, arg, None) is not None]
            f.write("  { X86Arch::%s, rep_%s, %d },\n"
                    % (name, obj.semantics, len(recorded_args)))
        elif isinstance(obj, (syscalls.IrregularSyscall, syscalls.RestartSyscall)):
            f.write("  { X86Arch::%s, rep_IRREGULAR, -1 },\n" % name)
        elif isinstance(obj, syscalls.UnsupportedSyscall):
            pass
    f.write("};\n")

def write_check_syscall_numbers(f):
    for name, obj in syscalls.all():
        f.write("""static_assert(X86Arch::%s == SYS_%s, "Incorrect syscall number for %s");\n"""
                % (name, name, name))

generators_for = {
    'CheckSyscallNumbers': write_check_syscall_numbers,
    'IsAlwaysEmulatedSyscall': write_is_always_emulated_syscall,
    'SyscallDefsTable': write_syscall_defs_table,
    'SyscallEnumsX86': lambda f: write_syscall_enum(f, 'x86'),
    'SyscallEnumsX64': lambda f: write_syscall_enum(f, 'x64'),
    'SyscallnameArch': write_syscallname_arch,
    'SyscallRecordCase': write_syscall_record_cases,
    'SyscallHelperFunctions': write_syscall_helper_functions,
}

def main(argv):
    filename = argv[0]
    base, extension = os.path.splitext(os.path.basename(filename))

    with open(filename, 'w') as f:
        generators_for[base](f)

if __name__ == '__main__':
    main(sys.argv[1:])

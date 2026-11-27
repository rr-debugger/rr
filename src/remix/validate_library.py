#!/usr/bin/env python3

import re
import subprocess
import sys

# Validate relocations
reloc_re = re.compile('.*(R_[A-Z0-9_]+).*')

pipe = subprocess.Popen("objdump -R %s"%sys.argv[1], shell=True, bufsize=4096, stdout=subprocess.PIPE, encoding='utf-8').stdout
for line in pipe:
    m = reloc_re.match(line)
    if m and m.group(1) != 'R_X86_64_RELATIVE':
        print('Unsupported relocation:', file=sys.stderr)
        print(line, file=sys.stderr)
        sys.exit(1)

# Validate XMM usage
# Strip '.' and following chars from the function name
func_re = re.compile('[0-9a-f]+ <([^>.]*)[^>]*>:')

all_libs_xmm_allowed = {
    "save_xmm_state": True,
    "restore_xmm_state": True,
    "rpl_vsnprintf": True,
    "rpl_snprintf": True,
    "opnd_is_abs_base_disp": True,
    "opnd_is_abs_addr": True,
    "opnd_create_immed_int": True,
    "opnd_create_immed_uint": True,
    "opnd_create_immed_int64": True,
    "opnd_create_immed_float": True,
    "opnd_create_immed_double": True,
    "opnd_create_increment_reg": True,
    "opnd_get_immed_float": True,
    "opnd_get_immed_double": True,
    "opnd_get_vector_element_size": True,
    "opnd_create_far_pc": True,
    "opnd_create_instr_ex": True,
    "opnd_create_far_instr": True,
    "opnd_create_mem_instr": True,
    "opnd_disassemble": True,
    "opnd_get_segment_selector": True,
    "opnd_get_shift": True,
    "opnd_get_mem_instr_disp": True,
    "opnd_get_addr": True,
    "opnd_invert_immed_int": True,
    "opnd_is_element_vector_reg": True,
    "reg_get_value_ex": True,
    "reg_set_value_ex": True,
    "reg_set_value_ex_priv": True,
    "opnd_same": True,
    "opnd_create_reg_partial": True,
    "opnd_create_reg_ex": True,
    "opnd_create_reg_element_vector": True,
    "instr_create": True,
    "instr_init": True,
    "instr_convert_to_isa_regdeps": True,
    "instr_reuse": True,
    "instr_remove_srcs": True,
    "instr_clone": True,
    "instrlist_init": True,
    "instrlist_append": True,
    "instrlist_prepend": True,
    "instrlist_remove": True,
    "read_operand": True,
    "decode_common": True,
    "decode_info_init_for_instr": True,
    "instr_encode_arch": True,
    "internal_opnd_disassemble": True,
    "internal_instr_disassemble": True,
    "double_print": True,
    "double_to_str": True,
    "double_to_str_wide": True,
    "d_r_vsnprintf": True,
    "d_r_vsnprintf_wide": True,
    "d_r_snprintf": True,
    "d_r_snprintf_wide": True,
    "d_r_sscanf": True,
    "double2int_trunc": True,
    "print_to_buffer": True,
    "print_file": True,
    "open": True,
    "mremap": True,
    "fmtflt": True,
    "getexponent": True,
    "cast": True,
    "myround": True,
    "mypow10": True,
    "instr_replace_reg_resize": True,
    "opnd_replace_reg": True,
    "opnd_replace_reg_resize": True,
    "correct_single_rcp_rsqrt_stub": True,
    "correct_packed_rcp_rsqrt_stub": True,
    "correct_single_vex_rcp_rsqrt_stub": True,
    "correct_packed_vex_rcp_rsqrt_stub": True,
    "opnd_invert_immed_int": True,
}
this_lib_xmm_allowed = {}
if sys.argv[1].endswith("_WriteRecorderTool.so"):
    this_lib_xmm_allowed = {
        "masked_move_stub_16": True,
        "masked_move_stub_32_no_avx512": True,
        "masked_move_stub_32_avx512": True,
        "masked_move_stub_dword_lane_evex_lo": True,
        "masked_move_stub_dword_lane_evex_hi": True,
        "masked_move_stub_qword_lane_evex_lo": True,
        "masked_move_stub_qword_lane_evex_hi": True,
    }

pipe = subprocess.Popen("objdump -d %s"%sys.argv[1], shell=True, bufsize=4096, stdout=subprocess.PIPE, encoding='utf-8').stdout
xmm_allowed = False
f = None
last_failed_function = None
for line in pipe:
    m = func_re.match(line)
    if m:
        f = m.group(1)
        xmm_allowed = f in all_libs_xmm_allowed or f in this_lib_xmm_allowed
    if "%xmm" in line and not xmm_allowed and last_failed_function != f:
        print("Found unexpected XMM usage in %s: %s"%(f, line), file=sys.stderr, end="")
        last_failed_function = f
if last_failed_function != None:
    sys.exit(1)

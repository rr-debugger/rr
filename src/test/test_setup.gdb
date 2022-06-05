set pagination off
handle SIGSEGV stop
handle SIGKILL nostop
# This fails in gdb < 8.3
set style enabled off
# gdb >= 10
set debuginfod enabled off

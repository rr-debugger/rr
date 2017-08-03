/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_MAIN_H_
#define RR_MAIN_H_

#include <string>
#include <vector>

namespace rr {

void assert_prerequisites(bool use_syscall_buffer = false);

void print_global_options(FILE*);
void print_usage(FILE*);

bool parse_global_option(std::vector<std::string>& args);

} // namespace rr

#endif // RR_MAIN_H_

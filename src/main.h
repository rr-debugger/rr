/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_MAIN_H_
#define RR_MAIN_H_

#include <string>
#include <vector>

void assert_prerequisites(bool use_syscall_buffer = false);

void check_performance_settings();

int print_usage();

bool parse_global_option(std::vector<std::string>& args);

#endif // RR_MAIN_H_

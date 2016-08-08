#!/bin/sh

find src -regex '.*\.\(c\|h\|cc\)$'|xargs clang-format -style=file -i

/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "../Generator.h"

class NullTool : public ToolBase {};

class NullToolHooks : public ToolHooksImpl<NullTool> {};

ToolHooks* tool_init(intptr_t*) { return new NullToolHooks(); }

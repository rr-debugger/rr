#!/usr/bin/env python3
""" rr-gdb-script-host.py <user-gdb-script> <primary binary name>"""
# Performs a limited emulation of the runtime environment of gdb scripts so that
# we can run them for `rr sources` to locate debug information.
from typing import Optional, List, Callable
import logging
import os
import signal
import sys

def strip_prefix(s: str, needle: str) -> Optional[str]:
    if s.startswith(needle):
        return s[len(needle):]

    return None

def print_wrapper(*args, **kwargs):
    # Don't allow the script to print to stdout and interfere
    # with our communication with the rr process.
    f = kwargs.get("file")
    if f is None or f == sys.stdout:
        kwargs["file"] = sys.stderr
    print(*args, **kwargs)

GdbNewObjfileEventCallback = Callable[[object], None]

class DebuggerExtensionCommand:
    def __init__(self, *args, **kwargs):
        logging.debug("DebuggerExtensionCommand(%s, %s)" % (args, kwargs))

class GdbScriptHost:
    """ The filename of the main symbol file """
    _filename: str = ""
    """ The current value of the gdb dir """
    _dir: str = ""
    """ The current value of debug-file-directory """
    debug_file_directory: str = "/usr/lib/debug"

    new_objfile_events: List[GdbNewObjfileEventCallback] = []

    def __init__(self, *args, **kwargs):
        self._filename = args[0]

    def show(self, cmd: str) -> Optional[str]:
        cmd.rstrip()
        if cmd == "debug-file-directory":
            return self.debug_file_directory
        if cmd == "dir":
            return "Source directories searched: %s:$cdir:$cwd"%self._dir

        return None

    def set(self, cmd: str) -> str:
        dfd = strip_prefix(cmd, "debug-file-directory ")
        if dfd:
            self.debug_file_directory = dfd
            # Prints nothing upon success.
            return ""

        # This seems to be the default error message.
        return "No symbol table is loaded.  Use the \"file\" command."

    def execute_script(self, script: str):
        gdb_api: GdbApiRoot = GdbApiRoot(self)
        exec(script, {'gdb': gdb_api, "print": print_wrapper})

    def new_objfile(self, f: str):
        new_objfile: GdbNewObjfile = GdbNewObjfile(self, f)
        new_objfile_event: GdbNewObjfileEvent = GdbNewObjfileEvent(self, new_objfile)
        for callback in self.new_objfile_events:
            callback(new_objfile_event)

class GdbApiObject(object):
    def __init__(self, *args, **kwargs):
        self.gdb = args[0]

    def __getattr__(self, attr):
        logging.warning("Accessing unsupported GDB api %s.%s" % (self.__class__.__name__, attr))

class GdbProgspace(GdbApiObject):
    filename: str

    def __init__(self, *args, **kwargs):
        GdbApiObject.__init__(self, *args, **kwargs)
        self.filename = self.gdb._filename

class GdbNewObjfile(GdbApiObject):
    filename: str
    def __init__(self, *args, **kwargs):
        GdbApiObject.__init__(self, *args, **kwargs)
        self.filename = args[1]

class GdbNewObjfileEvent(GdbApiObject):
    new_objfile: GdbNewObjfile

    def __init__(self, *args, **kwargs):
        GdbApiObject.__init__(self, *args, **kwargs)
        self.new_objfile = args[1]

class GdbNewObjfileEvents(GdbApiObject):
    def connect(self, c: GdbNewObjfileEventCallback):
        logging.debug("EventRegistry.connect")
        self.gdb.new_objfile_events.append(c)

class GdbApiEvents(GdbApiObject):
    _new_objfile: Optional[GdbNewObjfileEvents] = None

    @property
    def new_objfile(self) -> GdbNewObjfileEvents:
        logging.debug("gdb.events.new_objfile")
        if self._new_objfile == None:
            self._new_objfile = GdbNewObjfileEvents(self.gdb)
        return self._new_objfile

class GdbApiRoot(GdbApiObject):
    _events: Optional[GdbApiEvents] = None
    _current_progspace: Optional[GdbProgspace] = None

    def execute(self, command: str, from_tty: bool = False, to_string: bool = False) -> Optional[str]:
        logging.debug("gdb.execute(\"%s\", from_tty=%s, to_string=%s)" % (command, str(from_tty), str(to_string)))
        if from_tty:
            logging.warning("Unsupported gdb.execute with from_tty == True")
            return None

        remainder = strip_prefix(command, "show ")
        if remainder:
            r = self.gdb.show(remainder)
            if to_string:
                return r
            else:
                print(r, file=sys.stderr)
                return None
        remainder = strip_prefix(command, "set ")
        if remainder:
            r = self.gdb.set(remainder)
            if to_string:
                return r
            else:
                print(r, file=sys.stderr)
                return None
        remainder = strip_prefix(command, "dir ")
        if remainder:
            self.gdb._dir = remainder
            s = "Source directories searched: %s:$cdir:$cwd"%remainder
            if to_string:
                return s
            else:
                print(s, file=sys.stderr)
                return None

        logging.warning("Unsupported gdb.execute \"%s\""%command)
        return None

    def lookup_global_symbol(self, s: str) -> Optional[object]:
        #logging.debug("gdb.lookup_global_symbol(\"%s\")"%s)
        logging.warning("gdb.lookup_global_symbol(\"%s\") is not yet implemented, pretending we found something"%s)
        return object()

    def current_progspace(self) -> GdbProgspace:
        logging.debug("gdb.current_progspace()")
        if self._current_progspace == None:
            self._current_progspace = GdbProgspace(self.gdb)
        return self._current_progspace

    @property
    def events(self) -> GdbApiEvents:
        logging.debug("gdb.events")
        if self._events == None:
            self._events = GdbApiEvents(self.gdb)
        return self._events

    @property
    def COMMAND_USER(self) -> int:
        return 13

    @property
    def Command(self) -> DebuggerExtensionCommand:
        return DebuggerExtensionCommand

if __name__ == '__main__':
    with open(sys.argv[1], 'r') as user_script_file:
        user_script = user_script_file.read()
        host = GdbScriptHost(sys.argv[2])
        try:
            host.execute_script(user_script)
        except NameError as e:
            if getattr(e, "name", None) == "python" or e == "NameError: name 'python' is not defined":
                # This might be a gdb script that wraps a python script.
                start = user_script.find("python") + len("python")
                end = user_script.find("end")
                if end == -1:
                    raise(e)
                user_script = user_script[start:end]
                try:
                    host.execute_script(user_script)
                except:
                    raise(e)

        print("%s\n%s" % (host.debug_file_directory, host._dir), flush=True)
        for line in sys.stdin:
            line = line.rstrip()
            logging.debug("Processing %s"%line)
            host.new_objfile(line)
            print("%s\n%s" % (host.debug_file_directory, host._dir), flush=True)

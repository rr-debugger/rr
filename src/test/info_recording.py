from util import *

import re
import json

send_gdb('info recording')
expect_gdb(re.compile(r'(?<=Path of recording: ).*'))
path_jsonstr = last_match().group(0)
path_pystr   = json.loads(path_jsonstr)

if len(path_pystr) < 6:
    failed("ERROR ... Unreasonably short path for recording file found in output")

# Inferior command also has the name of the binary at the end,
# so the pattern matches opening but not closing paren.
send_gdb("inferior")
expect_gdb(f"\\({path_pystr}")

ok()

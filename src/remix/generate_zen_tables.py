#!/usr/bin/env python3

import subprocess
import sys

out = open(sys.argv[1], "w")
print("""struct RcpRsqrtEmulationTable {
  int values[22];
  char deltas[1 << 21];
};""", file=out)

def write_table(table_name, values):
    pipe = subprocess.Popen(["zstdcat", "%s/%s_deltas.zstd"%(sys.path[0], table_name)], stdout=subprocess.PIPE).stdout
    buf = pipe.read()
    print("static const RcpRsqrtEmulationTable %s_table = {"%table_name, file=out)
    print("{%s},{"%(",".join(map(hex, values))), file=out)
    index = 0
    for b in buf:
        print("%d,"%b, end="", file=out)
        index += 1
        if index%64 == 0:
            print(file=out)
    print("}};", file=out)
    print("const RcpRsqrtEmulationTable* %s() { return &%s_table; }"%(table_name, table_name), file=out);

write_table("zen_rcp", [0,
  0x0800,
  0x1000,
  0x1800,
  0x3000,
  0x3800,
  0x7000,
  0x7800,
  0xf000,
  0xf800,
  0x01f000,
  0x01f800,
  0x03f800,
  0x07f800,
  0x0ff000,
  0x0ff800,
  0x1ff800])
write_table("zen_rsqrt", [0,
  0x0800,
  0x1000,
  0x1800,
  0x3000,
  0x3800,
  0x7000,
  0x7800,
  0xf000,
  0xf800,
  0x01f000,
  0x01f800,
  0x03f000,
  0x03f800,
  0x07f000,
  0x07f800,
  0x0ff000,
  0x0ff800,
  0x1ff000,
  0x1ff800,
  0x3ff800,
  0x7ff800])

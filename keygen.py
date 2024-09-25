#generates keys and ivs

import sys
import os
if len(sys.argv) < 2:
    exit(1)

length = int(sys.argv[1])

print(os.urandom(length).hex())
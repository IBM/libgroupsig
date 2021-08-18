#!/usr/bin/env python3

import sys

from pygroupsig import groupsig
from pygroupsig import memkey
from pygroupsig import grpkey
from pygroupsig import message
from pygroupsig import constants

if len(sys.argv) != 4:
    print ("Usage: $python3 join-seq3.py <grpkey str> <memkey str> <cert str>")
    sys.exit()

# Init scheme
groupsig.init(constants.GL19_CODE, 0)

# Import grpkey from the string received from the command line
gpk = grpkey.grpkey_import(constants.GL19_CODE, sys.argv[1])

# Import initial member key
usk = memkey.memkey_import(constants.GL19_CODE, sys.argv[2])

# Run second join member operation
msgin = message.message_from_base64(sys.argv[3])#.encode())
msgout = groupsig.join_mem(3, gpk, msgin = msgin, memkey = usk)
usk = msgout['memkey']

# Print the challenge response and the temporary key
print("Member key: %s" % memkey.memkey_export(usk))

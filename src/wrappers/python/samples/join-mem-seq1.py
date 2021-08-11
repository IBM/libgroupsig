#!/usr/bin/env python3
import sys

from pygroupsig import groupsig
from pygroupsig import memkey
from pygroupsig import grpkey
from pygroupsig import message
from pygroupsig import constants

if len(sys.argv) != 3:
    print ("Usage: $python3 join-mem-seq1.py <grpkey str> <challenge str>");
    sys.exit();

# Init scheme
groupsig.init(constants.GL19_CODE, 0)

# Import grpkey from the string received from the command line
gpk = grpkey.grpkey_import(constants.GL19_CODE, sys.argv[1])

# Run second join member operation
msgin = message.message_from_base64(sys.argv[2]);
msgout = groupsig.join_mem(1, gpk, msgin = msgin)
usk = msgout['memkey']

# Print the challenge response and the temporary key
response = msgout['msgout']
print("Response: %s" % message.message_to_base64(response));
print("Temporary member key: %s" % memkey.memkey_export(usk));

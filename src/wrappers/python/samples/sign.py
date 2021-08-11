import sys

from pygroupsig import groupsig
from pygroupsig import signature
from pygroupsig import blindsig
from pygroupsig import memkey
from pygroupsig import grpkey
from pygroupsig import mgrkey
from pygroupsig import bldkey
from pygroupsig import constants

if len(sys.argv) != 4:
    print ("Usage: $python3 sign.py <grpkey str> <memkey str> <message>");
    sys.exit();

# Init scheme
groupsig.init(constants.GL19_CODE, 0)

# Import grpkey
gpk = grpkey.grpkey_import(constants.GL19_CODE, sys.argv[1])

# Import mem key
usk = memkey.memkey_import(constants.GL19_CODE, sys.argv[2])

# Read file
sig = groupsig.sign(sys.argv[3], usk, gpk)

ssig = signature.signature_export(sig)
print("Signature: %s" % ssig)

#!/usr/bin/env python3
from pygroupsig import groupsig
from pygroupsig import signature
from pygroupsig import memkey
from pygroupsig import grpkey
from pygroupsig import mgrkey
from pygroupsig import gml
from pygroupsig import identity
from pygroupsig import constants

# Setup
bbs04 = groupsig.setup(constants.BBS04_CODE)
gpk = bbs04['grpkey']
msk = bbs04['mgrkey']
gml = bbs04['gml']

# Join
msg1 = groupsig.join_mgr(0, msk, gpk, gml = gml)
msg2 = groupsig.join_mem(1, gpk, msgin = msg1)
usk = msg2['memkey']

# Sign
sig = groupsig.sign("Hello, World!", usk, gpk)

# Verify
b = groupsig.verify(sig, "Hello, World!", gpk)

if b == True:
    print ("VALID signature.")
else:
    print ("WRONG signature.")
    sys.exit()

# Open
id = groupsig.open(sig, msk, gpk, gml)
str = identity.identity_to_string(id)

print("Identity: %s" % str)

groupsig.clear(constants.BBS04_CODE, bbs04['config'])


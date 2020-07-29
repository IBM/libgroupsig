#!/usr/bin/env python3

from pygroupsig import groupsig
from pygroupsig import signature
from pygroupsig import memkey
from pygroupsig import grpkey
from pygroupsig import mgrkey
from pygroupsig import constants

# Setup
issuer = groupsig.setup(constants.GL19_CODE)
_gpk = issuer['grpkey']
isk = issuer['mgrkey']
converter = groupsig.setup(constants.GL19_CODE, _gpk);
csk = converter['mgrkey']
gpk = converter['grpkey']

# Join
msg1 = groupsig.join_mgr(0, isk, gpk)
msg2 = groupsig.join_mem(1, gpk, msgin = msg1)
usk = msg2['memkey']
msg3 = groupsig.join_mgr(2, isk, gpk, msg2['msgout'])
msg4 = groupsig.join_mem(3, gpk, msgin = msg3, memkey = usk)
usk = msg4['memkey']

# Sign
sig = groupsig.sign("Hello, World!", usk, gpk)

# Verify
b = groupsig.verify(sig, "Hello, World!", gpk)

if b == True:
    print ("VALID signature.")
else:
    print ("WRONG signature.")
    sys.exit()

groupsig.clear(constants.GL19_CODE, issuer['config'])
groupsig.clear(constants.GL19_CODE, converter['config'])

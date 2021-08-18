import sys

from pygroupsig import groupsig
from pygroupsig import signature
from pygroupsig import grpkey
from pygroupsig import bldkey
from pygroupsig import blindsig
from pygroupsig import constants

if len(sys.argv) != 6:
    print ("Usage: $python blind.py <grpkey str> <sig1 str> <msg1 str> <sig2 str> <msg2 str>");
    sys.exit();

groupsig.init(constants.GL19_CODE, 0)

# Import grpkey
gpk = grpkey.grpkey_import(constants.GL19_CODE, sys.argv[1])

# Import signatures
sig1 = signature.signature_import(constants.GL19_CODE, sys.argv[2])
sig2 = signature.signature_import(constants.GL19_CODE, sys.argv[4])

# Blind
bdk = bldkey.bldkey_random(constants.GL19_CODE, gpk)
out = groupsig.blind(gpk, sig1, sys.argv[3], bdk)
bsig1 = out['bsig']

out2 = groupsig.blind(gpk, sig2, sys.argv[5], bdk)
bsig2 = out2['bsig']

## Export Blinded sigs
sbsig1 = blindsig.blindsig_export(bsig1)
sbsig2 = blindsig.blindsig_export(bsig2)

## Export blinding key
sbdk_pub = bldkey.bldkey_export_pub(bdk)
sbdk = bldkey.bldkey_export(bdk)

## Output
print("Blinded sig1: %s" % sbsig1)
print("Blinded sig2: %s" % sbsig2)
print("Blinding public key: %s" % sbdk_pub)
print("Blinding keypair: %s" % sbdk)

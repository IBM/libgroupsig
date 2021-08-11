import sys

from pygroupsig import groupsig
from pygroupsig import bldkey
from pygroupsig import blindsig
from pygroupsig import constants

if len(sys.argv) != 4:
    print ("Usage: $python blind.py <bldkey str> <csig1 str> <csig2 str>");
    sys.exit();

groupsig.init(constants.GL19_CODE, 0)

# Import blinding key
bsk = bldkey.bldkey_import(constants.GL19_CODE, sys.argv[1])

# Import converted signatures
csig1 = blindsig.blindsig_import(constants.GL19_CODE, sys.argv[2])
csig2 = blindsig.blindsig_import(constants.GL19_CODE, sys.argv[3])

# Unblind
nym1 = groupsig.unblind(csig1, bsk)
nym2 = groupsig.unblind(csig2, bsk)

print ("Sig1:\n\tNym: %s\n\tMessage: %s" % (nym1['nym'], nym1['msg']))
print ("Sig2:\n\tNym: %s\n\tMessage: %s" % (nym2['nym'], nym2['msg']))

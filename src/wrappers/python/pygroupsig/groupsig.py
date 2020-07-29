from _groupsig import lib, ffi
from . import constants

from array import array

def hello_world():
    lib.groupsig_hello_world()
    return

def init(scheme, seed):

    if lib.groupsig_init(scheme, seed) == lib.IERROR:
        raise Exception('Error initializing groupsig environment.')

    return

def clear(scheme, config):

    if lib.groupsig_clear(scheme, config) == lib.IERROR:
        raise Exception('Error clearing groupsig environment.')

    return

def setup(scheme, grpkey=ffi.NULL, seed=0):

    if grpkey == ffi.NULL:
        _grpkey = lib.groupsig_grp_key_init(scheme)
    else:
        _grpkey = grpkey
    mgrkey = lib.groupsig_mgr_key_init(scheme)
    gml = lib.gml_init(scheme)
    config = lib.groupsig_init(scheme, seed)
    
    if lib.groupsig_setup(scheme, _grpkey, mgrkey, gml, config) == lib.IERROR:
        raise Exception('Error setting up scheme ' + scheme)

    return {
        'grpkey': _grpkey,
        'mgrkey': mgrkey,
        'gml': gml,
        'config': config
    }

def get_joinseq(scheme):

    msgs = ffi.new("uint8_t *")    

    if lib.groupsig_get_joinseq(scheme, msgs) == lib.IERROR:
        raise Exception('Error getting number of messages in Join.')

    return msgs

# returns 0 if the manager starts Join, 1 if the member starts Join
def get_joinstart(scheme):

    start = ffi.new("uint8_t *")

    if lib.groupsig_get_joinstart(scheme, start) == lib.IERROR:
        raise Exception('Error getting starting party in Join.')
    
    return start

def join_mgr(seq, mgrkey, grpkey, msgin = ffi.NULL, gml = ffi.NULL):

    msgout = ffi.new("message_t **")
    msgout[0] = ffi.NULL

    if lib.groupsig_join_mgr(msgout, gml, mgrkey, seq, msgin, grpkey) == lib.IERROR:
        raise Exception('Error running join_mgr operation.')

    return msgout[0]

def join_mem(seq, grpkey, msgin = ffi.NULL, memkey = ffi.NULL):

    msgout = ffi.new("message_t **")
    msgout[0] = ffi.NULL

    if memkey == ffi.NULL:
        _memkey = lib.groupsig_mem_key_init(grpkey.scheme)
    else:
        _memkey = memkey
        
    if lib.groupsig_join_mem(msgout, _memkey, seq, msgin, grpkey) == lib.IERROR:
        raise Exception('Error running join_mem operation.')

    return {
        'msgout' : msgout[0],
        'memkey' : _memkey
    }

def sign(msg, memkey, grpkey, seed=0):
    
    sig = lib.groupsig_signature_init(memkey.scheme)

    if isinstance(msg, bytes):
        _msg = lib.message_from_bytes(msg, len(msg))
    else:
        _msg = lib.message_from_string(msg.encode('utf8'))
        
    if lib.groupsig_sign(sig, _msg, memkey, grpkey, seed) == lib.IERROR:
        raise Exception('Error signing message.')

    return sig

def verify(sig, msg, grpkey):
    
    _b = ffi.new("uint8_t *")

    if isinstance(msg,bytes):
        _msg = lib.message_from_bytes(msg,len(msg))
    else:
        _msg = lib.message_from_string(msg.encode('utf8'))
    
    if lib.groupsig_verify(_b, sig, _msg, grpkey) == lib.IERROR:
        raise Exception('Error verifying message.')
    else:
        if _b[0] == 1:
            return True
        if _b[0] == 0:
            return False

def open(sig, mgrkey, grpkey, gml=ffi.NULL, crl=ffi.NULL, proof=ffi.NULL):

    identity = lib.identity_init(sig.scheme)

    if lib.groupsig_open(identity, proof, crl, sig, grpkey, mgrkey, gml) == lib.IERROR:
        raise Exception('Error opening signature')

    return identity

def blind(grpkey, sig, msg, bldkey=ffi.NULL):

    if bldkey == ffi.NULL:
        _bldkey = ffi.new("groupsig_key_t **")
        _bldkey[0] = ffi.NULL
    else:
        _bldkey = ffi.new("groupsig_key_t **")
        _bldkey[0] = bldkey

    bsig = lib.groupsig_blindsig_init(sig.scheme)

    if isinstance(msg,bytes):
        _msg = lib.message_from_bytes(msg,len(msg))
    else:
        _msg = lib.message_from_string(msg.encode('utf8'))
    
    if lib.groupsig_blind(bsig, _bldkey, grpkey, sig, _msg) == lib.IERROR:
        raise Exception('Error blinding signature.')

    if bldkey == ffi.NULL:
        return {
            'bldkey': _bldkey[0],
            'bsig' : bsig
        }

    else:
        return {
            'bldkey': _bldkey,
            'bsig' : bsig
        }

def convert(bsigs, grpkey, bldkey, msg=ffi.NULL, mgrkey=ffi.NULL):

    _csigs = [
        lib.groupsig_blindsig_init(grpkey.scheme) for i in range(len(bsigs))
    ]
    
    csigs = ffi.new("groupsig_blindsig_t* []", _csigs)

    if lib.groupsig_convert(csigs, bsigs, len(bsigs), grpkey, mgrkey, bldkey, msg) == lib.IERROR:
        raise Exception('Error converting signatures.')
    
    return csigs

def unblind(csig, bldkey, grpkey=ffi.NULL, sig=ffi.NULL):

    msg = lib.message_init()
    nym = lib.identity_init(csig.scheme)

    if lib.groupsig_unblind(nym, sig, csig, grpkey, bldkey, msg) == lib.IERROR:
        raise Exception('Error unblinding signature.')

    return {
        'nym' : ffi.string(lib.identity_to_string(nym)),
        'msg' : ffi.string(lib.message_to_base64(msg))
    }
    return 

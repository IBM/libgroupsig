from _groupsig import lib, ffi
from . import constants
import base64

def grpkey_export(grpkey):

    bkey = ffi.new("byte_t **")
    bkey[0] = ffi.NULL
    size = ffi.new("uint32_t *")
    if lib.groupsig_grp_key_export(bkey, size, grpkey) == constants.IERROR:
        raise Exception('Error exporting group key.')
    b64 = base64.b64encode(ffi.buffer(bkey[0],size[0]))    
    #    lib.free(bkey[0])
    return b64

def grpkey_import(code, b64key):

    b = base64.b64decode(b64key)
    grpkey = lib.groupsig_grp_key_import(code, b, len(b))
    if grpkey == ffi.NULL:
        raise Exception('Error importing group key.')
    return grpkey

#def grpkey_to_string(key):
#
#    _str = ffi.new("char *")
#    _str = lib.groupsig_grp_key_to_string(key)
#    if _str == ffi.NULL:
#        raise Exception('Error converting grpkey to string.')
#    return ffi.string(_str).decode('utf8')

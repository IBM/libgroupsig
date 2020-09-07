from _groupsig import lib, ffi
from . import constants
import base64

def bldkey_random(code, grpkey):
    return lib.groupsig_bld_key_random(code, grpkey)

def bldkey_export(bldkey):

    bkey = ffi.new("byte_t **")
    bkey[0] = ffi.NULL
    size = ffi.new("uint32_t *")      
    if lib.groupsig_bld_key_export(bkey, size, bldkey) == constants.IERROR:
        raise Exception('Error exporting blinding key.')
    b64key = base64.b64encode(ffi.buffer(bkey[0],size[0]))
    b64key = b64key.decode('utf-8').replace('\n', '')
#    lib.free(bkey[0])
    return b64key

def bldkey_export_pub(bldkey):

    bkey = ffi.new("byte_t **")
    bkey[0] = ffi.NULL
    size = ffi.new("uint32_t *")  
    if lib.groupsig_bld_key_export_pub(bkey, size, bldkey) == constants.IERROR:
        raise Exception('Error exporting blinding public key.')
    b64key = base64.b64encode(ffi.buffer(bkey[0],size[0]))
    b64key = b64key.decode('utf-8').replace('\n', '')    
#    lib.free(bkey[0])
    return b64key
    
def bldkey_import(code, b64key):

    b = base64.b64decode(b64key)
    bldkey = lib.groupsig_bld_key_import(code, b, len(b))
    if bldkey == ffi.NULL:
        raise Exception('Error importing blinding key.')
    return bldkey

#def bldkey_to_string(key):
#
#    _str = ffi.new("char *")
#    _str = lib.groupsig_bld_key_to_string(key)
#    if _str == ffi.NULL:
#        raise Exception('Error converting blinding key to string.')
#    return ffi.string(_str).decode('utf8')

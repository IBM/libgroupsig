from _groupsig import lib, ffi
from . import constants
import base64

def memkey_export(memkey):

    bkey = ffi.new("byte_t **")
    bkey[0] = ffi.NULL
    size = ffi.new("uint32_t *")
    if lib.groupsig_mem_key_export(bkey, size, memkey) == constants.IERROR:
        raise Exception('Error exporting member key.')
    b64key = base64.b64encode(ffi.buffer(bkey[0],size[0]))
    #    lib.free(bkey)
    return b64key    

def memkey_import(code, b64key):

    b = base64.b64decode(b64key)
    memkey = lib.groupsig_mem_key_import(code, b, len(b))
    if memkey == ffi.NULL:
        raise Exception('Error importing member key.')
    return memkey

def memkey_to_string(key):

    _str = ffi.new("char *")
    _str = lib.groupsig_mem_key_to_string(key)
    if _str == ffi.NULL:
        raise Exception('Error converting member key to string.')
    return ffi.string(_str).decode('utf8')

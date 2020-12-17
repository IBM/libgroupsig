from _groupsig import lib, ffi
from . import constants
import base64

def grpkey_export(grpkey):
    """
    Exports the given group key to a Base64 string.

    Parameters:
        grpkey: The native group key data structure.
    Returns:
        A Base64 string. On error, an Exception is thrown.
    """
    
    bkey = ffi.new("byte_t **")
    bkey[0] = ffi.NULL
    size = ffi.new("uint32_t *")
    if lib.groupsig_grp_key_export(bkey, size, grpkey) == constants.IERROR:
        raise Exception('Error exporting group key.')
    b64 = base64.b64encode(ffi.buffer(bkey[0],size[0]))
    b64 = b64.decode('utf-8').replace('\n', '')
    #    lib.free(bkey[0])
    return b64

def grpkey_import(code, b64key):
    """
    Imports a group key from a Base64 string.

    Parameters:
        code: The code corresponding to the group signature scheme.
        b64key: The Base64 string.
    Returns:
        A group key. On error, an Exception is thrown.
    """
    
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

from _groupsig import lib, ffi
from . import constants
import base64

def mgrkey_export(mgrkey):
    """
    Exports the given manager key to a Base64 string.

    Parameters:
        mgrkey: The native manager key data structure.
    Returns:
        A Base64 string. On error, an Exception is thrown.
    """
    
    bkey = ffi.new("byte_t **")
    bkey[0] = ffi.NULL
    size = ffi.new("uint32_t *")    
    if lib.groupsig_mgr_key_export(bkey, size, mgrkey) == constants.IERROR:
        raise Exception('Error exporting manager key.')
    b64key = base64.b64encode(ffi.buffer(bkey[0],size[0]))
    b64key = b64key.decode('utf-8').replace('\n', '')    
#    lib.free(bkey[0])
    return b64key

def mgrkey_import(code, b64key):
    """
    Imports a manager key from a Base64 string.

    Parameters:
        code: The code corresponding to the group signature scheme.
        b64key: The Base64 string.
    Returns:
        A manager key. On error, an Exception is thrown.
    """    

    b = base64.b64decode(b64key)    
    mgrkey = lib.groupsig_mgr_key_import(code, b, len(b))
    if mgrkey == ffi.NULL:
        raise Exception('Error importing manager key.')
    return mgrkey

#def mgrkey_to_string(key):
#
#    _str = ffi.new("char *")
#    _str = lib.groupsig_mgr_key_to_string(key)
#    if _str == ffi.NULL:
#        raise Exception('Error converting manager key to string.')
#    return ffi.string(_str).decode('utf8')

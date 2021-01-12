from _groupsig import lib, ffi
from . import constants
import base64

def memkey_export(memkey):
    """
    Exports the given member key to a Base64 string.

    Parameters:
        memkey: The native member key data structure.
    Returns:
        A Base64 string. On error, an Exception is thrown.
    """    

    bkey = ffi.new("byte_t **")
    bkey[0] = ffi.NULL
    size = ffi.new("uint32_t *")
    if lib.groupsig_mem_key_export(bkey, size, memkey) == constants.IERROR:
        raise Exception('Error exporting member key.')
    b64key = base64.b64encode(ffi.buffer(bkey[0],size[0]))
    b64key = b64key.decode('utf-8').replace('\n', '')    
    #    lib.free(bkey)
    return b64key    

def memkey_import(code, b64key):
    """
    Imports a member key from a Base64 string.

    Parameters:
        code: The code corresponding to the group signature scheme.
        b64key: The Base64 string.
    Returns:
        A member key. On error, an Exception is thrown.
    """

    b = base64.b64decode(b64key)
    memkey = lib.groupsig_mem_key_import(code, b, len(b))
    if memkey == ffi.NULL:
        raise Exception('Error importing member key.')
    return memkey

def memkey_to_string(key):
    """
    Returns a human readable string for the given member key.
    
    Parameters:
        key: The native member key data structure.
    Returns:
        A human readable string. On error, an Exception is thrown.
    """        

    _str = ffi.new("char *")
    _str = lib.groupsig_mem_key_to_string(key)
    if _str == ffi.NULL:
        raise Exception('Error converting member key to string.')
    return ffi.string(_str).decode('utf8')

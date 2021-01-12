from _groupsig import lib, ffi
from . import constants
import base64

def bldkey_random(code, grpkey):
    """
    Generates a random blinding keypair for schemes of the specified code.

    Parameters:
        code: The code specifying the type of scheme the key belongs to.
        grpkey: The group key of the scheme. Should contain all parameters
                needed to generate a random blinding key.
    Returns:
        A native data structure containing the blinding keypair. On error,
        an exception is thrown.
    """
    bldkey = lib.groupsig_bld_key_random(code, grpkey)
    if bldkey == ffi.NULL:
        raise Exception('Error importing blinding key.')
    return bldkey

def bldkey_export(bldkey):
    """
    Exports the given blinding keypair to a Base64 string.
    
    Parameters:
        bldkey: The blinding key to export.
    Returns:
        The produced Base64 string. On error, an Exception is thrown.
    """

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
    """
    Exports the public part of given blinding keypair to a Base64 string.
    
    Parameters:
        bldkey: The blinding key to export.
    Returns:
        The produced Base64 string. On error, an Exception is thrown.
    """    

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
    """
    Imports the given blinding keypair from a Base64 string. Works both for full
    keypairs and for public keys.
    
    Parameters:
        bldkey: The blinding key to export.
    Returns:
        The imported keypair. On error, an Exception is thrown.
    """    

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

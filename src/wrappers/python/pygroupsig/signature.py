from _groupsig import lib, ffi
from . import constants
import base64

def signature_export(sig):
    """
    Exports the given group signature a Base64 string.

    Parameters:
        sig: The native group signature data structure.
    Returns:
        A Base64 string. On error, an Exception is thrown.
    """

    bsig = ffi.new("byte_t **")
    bsig[0] = ffi.NULL
    size = ffi.new("uint32_t *")  
    if lib.groupsig_signature_export(bsig, size, sig) == constants.IERROR:
        raise Exception('Error exporting signature.')
    b64sig = base64.b64encode(ffi.buffer(bsig[0],size[0]))
    b64sig = b64sig.decode('utf-8').replace('\n', '')
    #    lib.free(bsig[0])
    return b64sig    

def signature_import(code, b64sig):
    """
    Imports a group signature from a Base64 string.

    Parameters:
        code: The code corresponding to the group signature scheme.
        b64sig: The Base64 string.
    Returns:
        A group signature. On error, an Exception is thrown.
    """    

    b = base64.b64decode(b64sig)
    sig = lib.groupsig_signature_import(code, b, len(b))
    if sig == ffi.NULL:
        raise Exception('Error importing signature.')
    return sig

def signature_to_string(sig):
    """
    Returns a human readable string for the given group signature.
    
    Parameters:
        sig: The group signature.
    Returns:
        A human readable string. On error, an Exception is thrown.
    """
    
    _str = ffi.new("char *")
    _str = lib.groupsig_signature_to_string(sig)
    if _str == ffi.NULL:
        raise Exception('Error converting signature to string.')
    return ffi.string(_str).decode('utf8')

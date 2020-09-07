from _groupsig import lib, ffi
from . import constants
import base64

def signature_export(sig):

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

    b = base64.b64decode(b64sig)
    sig = lib.groupsig_signature_import(code, b, len(b))
    if sig == ffi.NULL:
        raise Exception('Error importing signature.')
    return sig

def signature_to_string(sig):

    _str = ffi.new("char *")
    _str = lib.groupsig_signature_to_string(sig)
    if _str == ffi.NULL:
        raise Exception('Error converting signature to string.')
    return ffi.string(_str).decode('utf8')

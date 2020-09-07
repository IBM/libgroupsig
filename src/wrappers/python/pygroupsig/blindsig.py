from _groupsig import lib, ffi
from . import constants
import base64

def blindsig_export(sig):

    bsig = ffi.new("byte_t **")
    bsig[0] = ffi.NULL
    size = ffi.new("uint32_t *")
    if lib.groupsig_blindsig_export(bsig, size, sig) == constants.IERROR:
        raise Exception('Error exporting blindsig.')
    b64sig = base64.b64encode(ffi.buffer(bsig[0],size[0]))
    b64sig = b64sig.decode('utf-8').replace('\n', '')
    #    lib.free(bsig[0])
    return b64sig

def blindsig_import(code, b64sig):

    b = base64.b64decode(b64sig)
    sig = lib.groupsig_blindsig_import(code, b, len(b))
    if sig == ffi.NULL:
        raise Exception('Error importing blindsig.')
    return sig


def blindsig_to_string(sig):

    _str = ffi.new("char *")
    _str = lib.groupsig_blindsig_to_string(sig)
    if _str == ffi.NULL:
        raise Exception('Error converting blindsig to string.')
    return ffi.string(_str).decode('utf8')

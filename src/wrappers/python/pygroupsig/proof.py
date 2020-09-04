from _groupsig import lib, ffi
from . import constants
import base64

def proof_export(proof):

    bproof = ffi.new("byte_t **")
    bproof[0] = ffi.NULL
    size = ffi.new("uint32_t *")  
    if lib.groupsig_proof_export(bproof, size, proof) == constants.IERROR:
        raise Exception('Error exporting proof.')
    b64proof = base64.b64encode(ffi.buffer(bproof[0], size[0]))
#    lib.free(bproof[0])
    return b64proof    

def proof_import(code, b64proof):

    b = base64.b64decode(b64proof)
    proof = lib.groupsig_proof_import(code, b, len(b))
    if proof == ffi.NULL:
        raise Exception('Error importing proof.')
    return proof

def proof_to_string(proof):

    _str = ffi.new("char *")
    _str = lib.groupsig_proof_to_string(proof)
    if _str == ffi.NULL:
        raise Exception('Error converting proof to string.')
    return ffi.string(_str).decode('utf8')

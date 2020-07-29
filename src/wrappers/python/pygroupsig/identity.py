from _groupsig import lib, ffi
from . import constants

def identity_init(code):
    identity = lib.identity_init(code)
    if identity == ffi.NULL:
        raise Exception('Error initializing identity.')
    return identity

def identity_free(identity):
    return lib.identity_free(identity)

def identity_cmp(id1, id2):
    return lib.identity_cmp(id1, id2)

def identity_to_string(identity):
    string = lib.identity_to_string(identity)
    if string == ffi.NULL:
        raise Exception('Error converting id to string.')
    return ffi.string(string).decode('utf8')

def identity_from_string(string):
    identity = lib.identity_from_string(string)
    if identity == ffi.NULL:
        raise Exception('Error getting id from string.')
    return identity

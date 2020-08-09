from _groupsig import lib, ffi
from . import constants

def identity_init(code):
    """
    Initializes an identity for schemes of the specified type.

    Parameters:
        code: The group signature scheme code.
    Returns:
        A native identity data structure. On error, an Exception is thrown.
    """
    
    identity = lib.identity_init(code)
    if identity == ffi.NULL:
        raise Exception('Error initializing identity.')
    return identity

def identity_free(identity):
    """
    Frees the memory used for the given identity.

    Parameters:
        identity: The identity data to free.
    """
    
    return lib.identity_free(identity)

def identity_cmp(id1, id2):
    """
    Compares two identities.

    Parameters:
        id1: The first identity.
        id2: The second identity.
    Returns:
        0 if the identities are the same, not 0 if they are different.
    """
    
    return lib.identity_cmp(id1, id2)

def identity_to_string(identity):
    """
    Exports the given identity to a string.

    Parameters:
        identity: The identity to export.
    Returns:
        A string. On error, an Exception is thrown.
    """
    
    string = lib.identity_to_string(identity)
    if string == ffi.NULL:
        raise Exception('Error converting id to string.')
    return ffi.string(string).decode('utf8')

def identity_from_string(string):
    """
    Imports an identity from the given string.

    Parameters:
        string: The string containing the identity to import.
    Returns:
        An identity. On error, an Exception is thrown.
    """

    identity = lib.identity_from_string(string)
    if identity == ffi.NULL:
        raise Exception('Error getting id from string.')
    return identity

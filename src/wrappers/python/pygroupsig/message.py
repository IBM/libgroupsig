from _groupsig import lib, ffi
from . import constants

def message_from_string(mstr):

    msg = lib.message_from_string(mstr.encode('utf8'))
    if msg == ffi.NULL:
        raise Exception('Error parsing message the given string.')
    return msg

def message_to_string(msg):
    
    _str = ffi.new("char *")
    _str = lib.message_to_string(msg)
    if _str == ffi.NULL:
        raise Exception('Error converting message to string.')
    return ffi.string(_str).decode('utf8')

def message_from_base64(b64):

    msg = lib.message_from_base64(b64.encode('utf8'))
    if msg == ffi.NULL:
        raise Exception('Error parsing message the given Base64 string.')
    return msg

def message_to_base64(msg):

    _str = ffi.new("char *")
    _str = lib.message_to_base64(msg)
    if _str == ffi.NULL:
        raise Exception('Error converting message to a Base64 string.')
    return ffi.string(_str).decode('utf8')

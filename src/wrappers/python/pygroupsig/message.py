from _groupsig import lib, ffi
from . import constants
import base64

def message_from_string(mstr):
    """
    Imports a message from a UTF-8 string.

    Parameters:
        mstr: The string.
    Returns:
        A message data structure. On error, an Exception is thrown.
    """

    msg = lib.message_from_string(mstr.encode('utf8'))
    if msg == ffi.NULL:
        raise Exception('Error parsing message the given string.')
    return msg

def message_to_string(msg):
    """
    Exports the given message object to a UTF-8 string. Use only for messages
    that are ensured to be strings.

    Parameters:
        msg: The message to export to a string.
    Returns:
        A UTF-8 string. On error, an Exception is thrown.
    """    
    
    _str = ffi.new("char *")
    _str = lib.message_to_string(msg)
    if _str == ffi.NULL:
        raise Exception('Error converting message to string.')
    return ffi.string(_str).decode('utf8')

def message_from_base64(b64):
    """
    Imports a message from a Base64 string.

    Parameters:
        b64: The Base64 string.
    Returns:
        A message data structure. On error, an Exception is thrown.
    """

    b = base64.b64decode(b64)
    msg = lib.message_from_bytes(b, len(b))
    if msg == ffi.NULL:
        raise Exception('Error parsing message the given Base64 string.')
    return msg

def message_to_base64(msg):
    """
    Exports the given message object to a Base64 string.

    Parameters:
        msg: The message to export to a string.
    Returns:
        A Base64 string. On error, an Exception is thrown.
    """
    
    _str = ffi.new("char *")
    _str = lib.message_to_base64(msg)
    if _str == ffi.NULL:
        raise Exception('Error converting message to a Base64 string.')
    return ffi.string(_str).decode('utf8')

from _groupsig import lib, ffi
from . import constants
import base64

def gml_init(code):
    """
    Initializes a Group Membership List (GML) for schemes of the given type.
    
    Parameters:
        code: The code of the scheme.
    Returns:
        A native object representing the GML. Throws an Exception on error.
    """    
    gml = lib.gml_init(code)
    if gml == ffi.NULL:
        raise Exception('Error initializing GML.')
    return gml

def gml_free(gml):
    """
    Frees the native memory used to represent the given GML.
    
    Parameters:
        gml: The GML structure to free.
    Returns:
        IOK (1) or IERROR (0)
    """    
    return lib.gml_free(gml)

def gml_export(gml):
    """
    Exports a GML to a Base64 string.
    
    Parameters:
        gml: The GML to export.
    Returns:
        A Base64 string. On error, an Exception is thrown.
    """    

    bgml = ffi.new("byte_t **")
    bgml[0] = ffi.NULL
    size = ffi.new("uint32_t *")
    if lib.gml_export(bgml, size, gml) == constants.IERROR:
        raise Exception('Error exporting GML.')
    b64gml = base64.b64encode(ffi.buffer(bgml[0],size[0]))
#    lib.free(bgml[0])
    return b64gml    

def gml_import(code, b64gml):
    """
    Imports a GML from a Base64 string.
    
    Parameters:
        code: The code of the scheme related to this GML.
        b64gml: The Base64 string.
    Returns:
        The imported GML native data structure. Throws an Exception on error.
    """    
    
    b = base64.b64decode(b64gml)
    gml = lib.gml_import(code, b, len(b))
    if gml == ffi.NULL:
        raise Exception('Error importing GML.')
    return gml

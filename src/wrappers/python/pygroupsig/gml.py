from _groupsig import lib, ffi
from . import constants

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

def gml_export(gml, filename):
    """
    Exports a GML to a file.
    
    Parameters:
        gml: The GML to export.
        filename: The name of the file to use to store the GML data.
    Returns:
        void. Throws an Exception on error.
    """    
    if lib.gml_export(gml, filename, lib.GML_FILE) == constants.IERROR:
        raise Exception('Error exporting GML to a file.')
    return

def gml_import(code, filename):
    """
    Imports a GML from the given file.
    
    Parameters:
        code: The code of the scheme related to this GML.
        filename: The name of the file to read the GML data from.
    Returns:
        The imported GML native data structure. Throws an Exception on error.
    """    
    
    gml = lib.gml_import(code, lib.GML_FILE, filename)
    if gml == ffi.NULL:
        raise Exception('Error importing GML.')
    return gml

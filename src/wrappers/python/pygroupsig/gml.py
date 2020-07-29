from _groupsig import lib, ffi
from . import constants

def gml_init(code):
    gml = lib.gml_init(code)
    if gml == ffi.NULL:
        raise Exception('Error initializing GML.')
    return gml

def gml_free(gml):
    return lib.gml_free(gml)

def gml_export(gml, filename):
    if lib.gml_export(gml, filename, lib.GML_FILE) == constants.IERROR:
        raise Exception('Error exporting GML to a file.')
    return

def gml_import(code, filename):
    gml = lib.gml_import(code, lib.GML_FILE, filename)
    if gml == ffi.NULL:
        raise Exception('Error importing GML.')
    return gml

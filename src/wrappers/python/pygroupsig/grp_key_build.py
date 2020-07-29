# file "grp_key_build.py"

from pygroupsig.common_build import ffibuilder
import pygroupsig.key_build

# Define data types

ffibuilder.cdef("""
typedef groupsig_key_init_f grp_key_init_f;
""")

ffibuilder.cdef("""
typedef groupsig_key_free_f grp_key_free_f;
""")

ffibuilder.cdef("""
typedef groupsig_key_copy_f grp_key_copy_f;
""")

ffibuilder.cdef("""
typedef groupsig_key_get_size_f grp_key_get_size_f;
""")

ffibuilder.cdef("""
typedef groupsig_key_prv_get_f grp_key_prv_get_f;
""")

ffibuilder.cdef("""
typedef groupsig_key_pub_get_f grp_key_pub_get_f;
""")

ffibuilder.cdef("""
typedef groupsig_key_prv_set_f grp_key_prv_set_f;
""")

ffibuilder.cdef("""
typedef groupsig_key_pub_set_f grp_key_pub_set_f;
""")

ffibuilder.cdef("""
typedef groupsig_key_export_f grp_key_export_f;
""")

ffibuilder.cdef("""
typedef groupsig_key_pub_export_f grp_key_pub_export_f;
""")

ffibuilder.cdef("""
typedef groupsig_key_prv_export_f grp_key_prv_export_f;
""")

ffibuilder.cdef("""
typedef groupsig_key_import_f grp_key_import_f;
""")

ffibuilder.cdef("""
typedef groupsig_key_prv_import_f grp_key_prv_import_f;
""")

ffibuilder.cdef("""
typedef groupsig_key_pub_import_f grp_key_pub_import_f;
""")

ffibuilder.cdef("""
typedef groupsig_key_to_string_f grp_key_to_string_f;
""")

ffibuilder.cdef("""
typedef groupsig_key_prv_to_string_f grp_key_prv_to_string_f;
""")

ffibuilder.cdef("""
typedef groupsig_key_pub_to_string_f grp_key_pub_to_string_f;
""")

ffibuilder.cdef("""
typedef struct {
uint8_t code;
grp_key_init_f init;
grp_key_free_f free;
grp_key_copy_f copy;
grp_key_export_f gexport;
grp_key_import_f gimport;
grp_key_to_string_f to_string;
grp_key_get_size_f get_size;
} grp_key_handle_t;
""")

ffibuilder.cdef("""
const grp_key_handle_t* groupsig_grp_key_handle_from_code(uint8_t code);
""")

ffibuilder.cdef("""
groupsig_key_t* groupsig_grp_key_init(uint8_t code);
""")

ffibuilder.cdef("""
int groupsig_grp_key_free(groupsig_key_t *key);
""")

ffibuilder.cdef("""
int groupsig_grp_key_copy(
groupsig_key_t *dst, 
groupsig_key_t *src);
""")

ffibuilder.cdef("""
int groupsig_grp_key_get_size(
groupsig_key_t *key);
""")

ffibuilder.cdef("""
int groupsig_grp_key_export(
unsigned char **dst, 
uint32_t *size, 
groupsig_key_t *key);
""")

ffibuilder.cdef("""
groupsig_key_t* groupsig_grp_key_import(
uint8_t code, 
unsigned char *src, 
uint32_t size);
""")

ffibuilder.cdef("""
char* groupsig_grp_key_to_string(groupsig_key_t *key);
""")

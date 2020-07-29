# file "bld_key_build.py"

from pygroupsig.common_build import ffibuilder

ffibuilder.cdef("""
typedef groupsig_key_init_f bld_key_init_f;
""")

ffibuilder.cdef("""typedef groupsig_key_free_f bld_key_free_f;""")

ffibuilder.cdef("""typedef groupsig_key_copy_f bld_key_copy_f;""")

ffibuilder.cdef("""
typedef groupsig_key_get_size_f bld_key_get_size_f;
""")

ffibuilder.cdef("""typedef groupsig_key_prv_get_f bld_key_prv_get_f;""")

ffibuilder.cdef("""typedef groupsig_key_pub_get_f bld_key_pub_get_f;""")

ffibuilder.cdef("""typedef groupsig_key_prv_set_f bld_key_prv_set_f;""")

ffibuilder.cdef("""typedef groupsig_key_pub_set_f bld_key_pub_set_f;""")

ffibuilder.cdef("""typedef groupsig_key_export_f bld_key_export_f;""")

ffibuilder.cdef("""typedef groupsig_key_pub_export_f bld_key_pub_export_f;""")

ffibuilder.cdef("""typedef groupsig_key_prv_export_f bld_key_prv_export_f;""")

ffibuilder.cdef("""typedef groupsig_key_import_f bld_key_import_f;""")

ffibuilder.cdef("""typedef groupsig_key_prv_import_f bld_key_prv_import_f;""")

ffibuilder.cdef("""typedef groupsig_key_pub_import_f bld_key_pub_import_f;""")

ffibuilder.cdef("""typedef groupsig_key_to_string_f bld_key_to_string_f;""")

ffibuilder.cdef("""
typedef groupsig_key_prv_to_string_f bld_key_prv_to_string_f;
""")

ffibuilder.cdef("""
typedef groupsig_key_pub_to_string_f bld_key_pub_to_string_f;
""")

ffibuilder.cdef("""
typedef struct {
uint8_t code;
bld_key_init_f init;
bld_key_free_f free;
bld_key_copy_f copy;
bld_key_export_f gexport;
bld_key_pub_export_f gexport_pub;
bld_key_prv_export_f gexport_prv;
bld_key_import_f gimport;
bld_key_to_string_f to_string;
bld_key_get_size_f get_size;
} bld_key_handle_t;
""")

ffibuilder.cdef("""
const bld_key_handle_t* groupsig_bld_key_handle_from_code(uint8_t code);
""")

ffibuilder.cdef("""
groupsig_key_t* groupsig_bld_key_init(uint8_t code);
""")

ffibuilder.cdef("""
int groupsig_bld_key_free(groupsig_key_t *key);
""")

ffibuilder.cdef("""
groupsig_key_t* groupsig_bld_key_random(uint8_t code, void *param);
""")

ffibuilder.cdef("""
int groupsig_bld_key_copy(groupsig_key_t *dst, groupsig_key_t *src);
""")

ffibuilder.cdef("""
int groupsig_bld_key_get_size(
groupsig_key_t *key);
""")

ffibuilder.cdef("""
int groupsig_bld_key_export(
unsigned char **bytes,
uint32_t *size,
groupsig_key_t *key);
""")

ffibuilder.cdef("""
int groupsig_bld_key_export_pub(
unsigned char **bytes,
uint32_t *size,
groupsig_key_t *key);
""")

ffibuilder.cdef("""
int groupsig_bld_key_export_prv(
unsigned char **bytes,
uint32_t *size,
groupsig_key_t *key);
""")

ffibuilder.cdef("""
groupsig_key_t* groupsig_bld_key_import(
uint8_t code, 
unsigned char *source,
uint32_t size);
""")

ffibuilder.cdef("""
char* groupsig_bld_key_to_string(groupsig_key_t *key);
""")

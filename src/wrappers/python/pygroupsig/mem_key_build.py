# file "mem_key_build.py"

from pygroupsig.common_build import ffibuilder

ffibuilder.cdef("""
typedef groupsig_key_init_f mem_key_init_f;
""")

ffibuilder.cdef("""
typedef groupsig_key_free_f mem_key_free_f;
""")

ffibuilder.cdef("""
typedef groupsig_key_copy_f mem_key_copy_f;
""")

ffibuilder.cdef("""
typedef groupsig_key_get_size_f mem_key_get_size_f;
""")

ffibuilder.cdef("""
typedef groupsig_key_prv_get_f mem_key_prv_get_f;
""")
ffibuilder.cdef("""
typedef groupsig_key_pub_get_f mem_key_pub_get_f;
""")
ffibuilder.cdef("""
typedef groupsig_key_prv_set_f mem_key_prv_set_f;
""")
ffibuilder.cdef("""
typedef groupsig_key_pub_set_f mem_key_pub_set_f;
""")

ffibuilder.cdef("""
typedef groupsig_key_export_f mem_key_export_f;
""")
ffibuilder.cdef("""
typedef groupsig_key_pub_export_f mem_key_pub_export_f;
""")
ffibuilder.cdef("""
typedef groupsig_key_prv_export_f mem_key_prv_export_f;
""")

ffibuilder.cdef("""
typedef groupsig_key_import_f mem_key_import_f;
""")

ffibuilder.cdef("""
typedef groupsig_key_prv_import_f mem_key_prv_import_f;
""")

ffibuilder.cdef("""
typedef groupsig_key_pub_import_f mem_key_pub_import_f;
""")

ffibuilder.cdef("""
typedef groupsig_key_to_string_f mem_key_to_string_f;
""")
ffibuilder.cdef("""
typedef groupsig_key_prv_to_string_f mem_key_prv_to_string_f;
""")

ffibuilder.cdef("""
typedef groupsig_key_pub_to_string_f mem_key_pub_to_string_f;
""")

ffibuilder.cdef("""
typedef struct {
uint8_t code;
mem_key_init_f init;
mem_key_free_f free;
mem_key_copy_f copy;
mem_key_get_size_f get_size;
mem_key_export_f gexport;
mem_key_import_f gimport;
mem_key_to_string_f to_string;
} mem_key_handle_t;
""")

ffibuilder.cdef("""
const mem_key_handle_t* groupsig_mem_key_handle_from_code(uint8_t code);
""")

ffibuilder.cdef("""
groupsig_key_t* groupsig_mem_key_init(uint8_t code);
""")

ffibuilder.cdef("""
int groupsig_mem_key_free(groupsig_key_t *key);
""")

ffibuilder.cdef("""
int groupsig_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src);
""")

ffibuilder.cdef("""
int groupsig_mem_key_get_size(
groupsig_key_t *key);
""")

ffibuilder.cdef("""
int groupsig_mem_key_export(
unsigned char **bytes,
uint32_t *size,
groupsig_key_t *key);
""")

ffibuilder.cdef("""
groupsig_key_t* groupsig_mem_key_import(
uint8_t code, 
unsigned char *source,
uint32_t size);
""")

ffibuilder.cdef("""
char* groupsig_mem_key_to_string(groupsig_key_t *key);
""")

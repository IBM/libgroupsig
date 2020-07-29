# file "signature_build.py"

from pygroupsig.common_build import ffibuilder

ffibuilder.cdef("""
typedef struct {
uint8_t scheme;
void *sig;
} groupsig_signature_t;
""")

ffibuilder.cdef("""
typedef groupsig_signature_t* (*groupsig_signature_init_f)(void);
""")

ffibuilder.cdef("""
typedef int (*groupsig_signature_free_f)(groupsig_signature_t *signature);
""")

ffibuilder.cdef("""
typedef int (*groupsig_signature_copy_f)(
groupsig_signature_t *dst, 
groupsig_signature_t *src);
""")

ffibuilder.cdef("""
typedef int (*groupsig_signature_get_size_f)(
groupsig_signature_t *sig);
""")

ffibuilder.cdef("""
typedef int (*groupsig_signature_export_f)(
unsigned char **bytes,
uint32_t *size,
groupsig_signature_t *signature);
""")

ffibuilder.cdef("""
typedef groupsig_signature_t* (*groupsig_signature_import_f)(
unsigned char *source,
uint32_t size);
""")

ffibuilder.cdef("""
typedef char* (*groupsig_signature_to_string_f)(
groupsig_signature_t *signature);
""")

ffibuilder.cdef("""
typedef struct {
uint8_t scheme;
groupsig_signature_init_f init;
groupsig_signature_free_f free;
groupsig_signature_copy_f copy;
groupsig_signature_get_size_f get_size;
groupsig_signature_export_f gexport;
groupsig_signature_import_f gimport;
groupsig_signature_to_string_f to_string;
} groupsig_signature_handle_t;
""") 

ffibuilder.cdef("""
const groupsig_signature_handle_t* groupsig_signature_handle_from_code(uint8_t code);
""")

ffibuilder.cdef("""
groupsig_signature_t* groupsig_signature_init(uint8_t code)
;""")

ffibuilder.cdef("""
int groupsig_signature_free(groupsig_signature_t *sig);
""")

ffibuilder.cdef("""
int groupsig_signature_copy(
groupsig_signature_t *dst, 
groupsig_signature_t *src);
""")

ffibuilder.cdef("""
int groupsig_signature_get_size(
groupsig_signature_t *sig);
""")

ffibuilder.cdef("""
int groupsig_signature_export(
unsigned char **bytes,
uint32_t *size,
groupsig_signature_t *sig);
""")

ffibuilder.cdef("""
groupsig_signature_t* groupsig_signature_import(
uint8_t code, 
unsigned char *source,
uint32_t size);
""")

ffibuilder.cdef("""
char* groupsig_signature_to_string(groupsig_signature_t *sig);
""")

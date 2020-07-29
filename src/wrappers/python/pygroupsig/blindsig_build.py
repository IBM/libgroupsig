# file "blindsig_build.py"

from pygroupsig.common_build import ffibuilder

ffibuilder.cdef("""
typedef struct {
uint8_t scheme;
void *sig;
} groupsig_blindsig_t;
""")

ffibuilder.cdef("""
typedef groupsig_blindsig_t* (*groupsig_blindsig_init_f)(void);
""")

ffibuilder.cdef("""
typedef int (*groupsig_blindsig_free_f)(groupsig_blindsig_t *blindsig);
""")

ffibuilder.cdef("""
typedef int (*groupsig_blindsig_copy_f)(groupsig_blindsig_t *dst, groupsig_blindsig_t *src);
""")

ffibuilder.cdef("""
typedef int (*groupsig_blindsig_get_size_f)(groupsig_blindsig_t *sig);
""")

ffibuilder.cdef("""
typedef int (*groupsig_blindsig_export_f)(unsigned char **bytes,
                                          uint32_t *size,
                                          groupsig_blindsig_t *blindsig);
""")

ffibuilder.cdef("""
typedef groupsig_blindsig_t* (*groupsig_blindsig_import_f)(unsigned char *source,
							   uint32_t size);
""")

ffibuilder.cdef("""
typedef char* (*groupsig_blindsig_to_string_f)(groupsig_blindsig_t *blindsig);
""")

ffibuilder.cdef("""
typedef struct {
uint8_t scheme;
groupsig_blindsig_init_f init;
groupsig_blindsig_free_f free;
groupsig_blindsig_copy_f copy;
groupsig_blindsig_get_size_f get_size;
groupsig_blindsig_export_f gexport;
groupsig_blindsig_import_f gimport;
groupsig_blindsig_to_string_f to_string;
} groupsig_blindsig_handle_t; 
""")

ffibuilder.cdef("""
const groupsig_blindsig_handle_t* groupsig_blindsig_handle_from_code(uint8_t code);
""")

ffibuilder.cdef("""
groupsig_blindsig_t* groupsig_blindsig_init(uint8_t code);
""")

ffibuilder.cdef("""
int groupsig_blindsig_free(groupsig_blindsig_t *sig);
""")

ffibuilder.cdef("""
int groupsig_blindsig_copy(groupsig_blindsig_t *dst, groupsig_blindsig_t *src);
""")

ffibuilder.cdef("""
int groupsig_blindsig_get_size(groupsig_blindsig_t *sig);
""")

ffibuilder.cdef("""
int groupsig_blindsig_export(
unsigned char **bytes, 
uint32_t *size, 
groupsig_blindsig_t *sig);
""")

ffibuilder.cdef("""
groupsig_blindsig_t* groupsig_blindsig_import(
uint8_t code, 
unsigned char *source, 
uint32_t size);
""")

ffibuilder.cdef("""
char* groupsig_blindsig_to_string(groupsig_blindsig_t *sig);
""")

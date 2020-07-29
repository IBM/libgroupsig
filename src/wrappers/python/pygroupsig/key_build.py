# file "key_build.py"

from pygroupsig.common_build import ffibuilder

# Define data types
ffibuilder.cdef("""
typedef enum {
GROUPSIG_KEY_GRPKEY, 
GROUPSIG_KEY_MGRKEY,
GROUPSIG_KEY_MEMKEY,
GROUPSIG_KEY_BLDKEY,
} groupsig_key_types;
""")

ffibuilder.cdef("""
typedef struct {
uint8_t scheme;
void *key;
} groupsig_key_t;
""")

ffibuilder.cdef("""
typedef groupsig_key_t* (*groupsig_key_init_f)(void);
""")

ffibuilder.cdef("""
typedef int (*groupsig_key_free_f)(groupsig_key_t *key);
""")
            
ffibuilder.cdef("""
typedef int (*groupsig_key_copy_f)(
groupsig_key_t *dst, 
groupsig_key_t *src);
""")

ffibuilder.cdef("""
typedef int (*groupsig_key_get_size_f)(
groupsig_key_t *key);
""")

ffibuilder.cdef("""
typedef groupsig_key_t* (*groupsig_key_prv_get_f)(groupsig_key_t *key);
""")

ffibuilder.cdef("""              
typedef groupsig_key_t* (*groupsig_key_pub_get_f)(groupsig_key_t *key);
""")
                                            
ffibuilder.cdef("""
typedef int (*groupsig_key_prv_set_f)(
void *dst, 
void *src);
""")

ffibuilder.cdef("""
typedef int (*groupsig_key_pub_set_f)(
void *dst, 
void *src);
""")
                                                            
ffibuilder.cdef("""
typedef int (*groupsig_key_export_f)(
unsigned char **bytes,
uint32_t *size,
groupsig_key_t *key);
""")
ffibuilder.cdef("""
typedef int (*groupsig_key_pub_export_f)(
unsigned char **bytes,
uint32_t *size,
groupsig_key_t *key);
""")

ffibuilder.cdef("""
typedef int (*groupsig_key_prv_export_f)(
unsigned char **bytes,
uint32_t *size,
groupsig_key_t *key);
""")

ffibuilder.cdef("""
typedef groupsig_key_t* (*groupsig_key_import_f)(
unsigned char *source,
uint32_t size);
""")

ffibuilder.cdef("""
typedef groupsig_key_t* (*groupsig_key_prv_import_f)(
unsigned char *source,
uint32_t size);
""")

ffibuilder.cdef("""
typedef groupsig_key_t* (*groupsig_key_pub_import_f)(
unsigned char *source,
uint32_t size);
""")

ffibuilder.cdef("""
typedef char* (*groupsig_key_to_string_f)(groupsig_key_t *key);
""")

ffibuilder.cdef("""
typedef char* (*groupsig_key_prv_to_string_f)(groupsig_key_t *key);
""")

ffibuilder.cdef("""
typedef char* (*groupsig_key_pub_to_string_f)(groupsig_key_t *key);
""")

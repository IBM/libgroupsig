# file "proof_build.py"

from pygroupsig.common_build import ffibuilder

ffibuilder.cdef("""
typedef struct {
uint8_t scheme;
void *proof;
} groupsig_proof_t;
""")

ffibuilder.cdef("""
typedef groupsig_proof_t* (*groupsig_proof_init_f)(void);
""")

ffibuilder.cdef("""
typedef int (*groupsig_proof_free_f)(groupsig_proof_t *proof);
""")

ffibuilder.cdef("""
typedef int (*groupsig_proof_get_size_f)(groupsig_proof_t *proof);
""")

ffibuilder.cdef("""
typedef int (*groupsig_proof_export_f)(
byte_t **bytes,
uint32_t *size,
groupsig_proof_t *proof);
""")

ffibuilder.cdef("""
typedef groupsig_proof_t* (*groupsig_proof_import_f)(
byte_t *source,
uint32_t size);
""")

ffibuilder.cdef("""
typedef char* (*groupsig_proof_to_string_f)(groupsig_proof_t *proof);
""")

ffibuilder.cdef("""
typedef struct {
uint8_t scheme;
groupsig_proof_init_f init;
groupsig_proof_free_f free;
groupsig_proof_get_size_f get_size;
groupsig_proof_export_f gexport;
groupsig_proof_import_f gimport;
groupsig_proof_to_string_f to_string;
} groupsig_proof_handle_t;
""")

ffibuilder.cdef("""
const groupsig_proof_handle_t* groupsig_proof_handle_from_code(uint8_t code);
""")

ffibuilder.cdef("""
groupsig_proof_t* groupsig_proof_init(uint8_t code);
""")

ffibuilder.cdef("""
int groupsig_proof_free(groupsig_proof_t *proof);
""")

ffibuilder.cdef("""
int groupsig_proof_get_size(groupsig_proof_t *proof);
""")

ffibuilder.cdef("""
int groupsig_proof_export(
byte_t **bytes,
uint32_t *size,
groupsig_proof_t *proof);
""")

ffibuilder.cdef("""
groupsig_proof_t* groupsig_proof_import(
uint8_t code, 
byte_t *bytes,
uint32_t size);
""")

ffibuilder.cdef("""
char* groupsig_proof_to_string(groupsig_proof_t *proof);
""")

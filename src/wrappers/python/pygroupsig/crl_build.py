# file "crl_build.py"

from pygroupsig.common_build import ffibuilder

ffibuilder.cdef("""
typedef enum {
CRL_FILE,
CRL_DATABASE,
} crl_format_t;
""")

ffibuilder.cdef("""
typedef struct {
uint8_t scheme;
void **entries;
uint64_t n;
} crl_t;
""")

ffibuilder.cdef("""
typedef crl_t* (*crl_init_f)(void);
""")

ffibuilder.cdef("""
typedef int (*crl_free_f)(crl_t *crl);
""")

ffibuilder.cdef("""
typedef int (*crl_insert_f)(crl_t *crl, void *entry);
""")

ffibuilder.cdef("""
typedef int (*crl_remove_f)(crl_t *crl, uint64_t index);
""")

ffibuilder.cdef("""
typedef void* (*crl_get_f)(crl_t *crl, uint64_t index);
""")

ffibuilder.cdef("""
typedef crl_t* (*crl_import_f)(crl_format_t format, void *src);
""")

ffibuilder.cdef("""
typedef int (*crl_export_f)(crl_t *crl, void *dst, crl_format_t format);
""")

ffibuilder.cdef("""
typedef int (*crl_entry_exists_f)(crl_t *crl, void *entry);
""")

ffibuilder.cdef("""
typedef int (*crl_trapdoor_exists_f)(crl_t *crl, trapdoor_t *trap);
""")

ffibuilder.cdef("""
typedef struct {
uint8_t scheme;
crl_init_f crl_init;
crl_free_f crl_free;
crl_insert_f crl_insert;
crl_remove_f crl_remove;
crl_get_f crl_get;
crl_import_f crl_import;
crl_export_f crl_export;
crl_entry_exists_f crl_entry_exists;
crl_trapdoor_exists_f crl_trapdoor_exists;
} crl_handle_t;
""")

ffibuilder.cdef("""
typedef int (*crl_cmp_entries_f)(void *entry1, void *entry2);
""")

ffibuilder.cdef("""
const crl_handle_t* crl_handle_from_code(uint8_t code);
""")

ffibuilder.cdef("""
crl_t* crl_init(uint8_t scheme);
""")

ffibuilder.cdef("""
int crl_free(crl_t *crl);
""")

ffibuilder.cdef("""
int crl_insert(crl_t *crl, void *entry);
""")

ffibuilder.cdef("""
int crl_remove(crl_t *crl, uint64_t index);
""")

ffibuilder.cdef("""
void* crl_get(crl_t *crl, uint64_t index);
""")

ffibuilder.cdef("""
crl_t* crl_import(uint8_t code, crl_format_t format, void *source);
""")

ffibuilder.cdef("""
int crl_export(crl_t *crl, void *dst, crl_format_t format);
""")

#ffibuilder.cdef("""
#void* crl_entry_init(crl_t *crl);
#""")

ffibuilder.cdef("""
int crl_compare_entries(int *eq, void *entry1, void *entry2, crl_cmp_entries_f cmp);
""")

ffibuilder.cdef("""
int crl_entry_exists(crl_t *crl, void *entry);
""")

ffibuilder.cdef("""
int crl_trapdoor_exists(crl_t *crl, trapdoor_t *trap);
""")

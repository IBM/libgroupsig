# file "gml_build.py"

from pygroupsig.common_build import ffibuilder

ffibuilder.cdef("""
typedef struct {
uint8_t scheme;
uint64_t id; 
void *data; 
} gml_entry_t;
""")

ffibuilder.cdef("""
typedef struct {
uint8_t scheme;
gml_entry_t **entries; 
uint64_t n; 
} gml_t;
""")

ffibuilder.cdef("""
typedef gml_t* (*gml_init_f)(void);
""")

ffibuilder.cdef("""
typedef int (*gml_free_f)(gml_t *gml);
""")

ffibuilder.cdef("""
typedef int (*gml_insert_f)(gml_t *gml, gml_entry_t *entry);
""")

ffibuilder.cdef("""
typedef int (*gml_remove_f)(gml_t *gml, uint64_t index);
""")

ffibuilder.cdef("""
typedef gml_entry_t* (*gml_get_f)(gml_t *gml, uint64_t index);
""")

ffibuilder.cdef("""
typedef int (*gml_export_f)(byte_t **bytes,
			    uint32_t *size,
			    gml_t *gml);
""")

ffibuilder.cdef("""
typedef gml_t* (*gml_import_f)(byte_t *bytes, uint32_t size);
""")

ffibuilder.cdef("""
typedef gml_entry_t* (*gml_entry_init_f)();
""")

ffibuilder.cdef("""
typedef int (*gml_entry_free_f)(gml_entry_t *entry);  
""")

ffibuilder.cdef("""
typedef int (*gml_entry_get_size_f)(gml_entry_t *entry);
""")

ffibuilder.cdef("""
typedef int (*gml_entry_export_f)(byte_t **bytes,
uint32_t *size,
gml_entry_t *entry);
""")

ffibuilder.cdef("""
typedef gml_entry_t* (*gml_entry_import_f)(byte_t *bytes, uint32_t size);
""")

ffibuilder.cdef("""
typedef char* (*gml_entry_to_string_f)(gml_entry_t *entry);  
""")

ffibuilder.cdef("""
typedef struct {
uint8_t scheme;
gml_init_f init;
gml_free_f free;
gml_insert_f insert;
gml_remove_f remove;
gml_get_f get;
gml_import_f gimport;
gml_export_f gexport;
gml_entry_init_f entry_init;
gml_entry_free_f entry_free;
gml_entry_get_size_f entry_get_size;
gml_entry_export_f entry_export;
gml_entry_import_f entry_import;
gml_entry_to_string_f entry_to_string;
} gml_handle_t;
""")

ffibuilder.cdef("""
typedef int (*gml_cmp_entries_f)(gml_entry_t *entry1, gml_entry_t *entry2);
""")

ffibuilder.cdef("""
const gml_handle_t* gml_handle_from_code(uint8_t code);
""")

ffibuilder.cdef("""
gml_t* gml_init(uint8_t scheme);
""")

ffibuilder.cdef("""
int gml_free(gml_t *gml);
""")

ffibuilder.cdef("""
int gml_insert(gml_t *gml, gml_entry_t *entry);
""")

ffibuilder.cdef("""
int gml_remove(gml_t *gml, uint64_t index);
""")

ffibuilder.cdef("""
gml_entry_t* gml_get(gml_t *gml, uint64_t index);
""")

ffibuilder.cdef("""
int gml_export(byte_t **bytes, uint32_t *size, gml_t *gml);
""")

ffibuilder.cdef("""
gml_t* gml_import(uint8_t code, byte_t *bytes, uint32_t size);
""")

ffibuilder.cdef("""
gml_entry_t* gml_entry_init(uint8_t code);
""")

ffibuilder.cdef("""
int gml_entry_free(gml_entry_t *entry);
""")

ffibuilder.cdef("""
int gml_entry_get_size(gml_entry_t *entry);
""")

ffibuilder.cdef("""
int gml_entry_export(byte_t **bytes, uint32_t *size, gml_entry_t *entry);
""")

ffibuilder.cdef("""
gml_entry_t* gml_entry_import(uint8_t code, byte_t *bytes, uint32_t size);
""")

ffibuilder.cdef("""
char* gml_entry_to_string(gml_entry_t *entry);
""")

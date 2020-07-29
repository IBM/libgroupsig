# file "gml_build.py"

from pygroupsig.common_build import ffibuilder

ffibuilder.cdef("""
typedef enum {
GML_FILE,
GML_DATABASE,
} gml_format_t;
""")

ffibuilder.cdef("""
typedef struct {
  uint8_t scheme;
  void **entries;
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
typedef int (*gml_insert_f)(gml_t *gml, void *entry);
""")

ffibuilder.cdef("""
typedef int (*gml_remove_f)(gml_t *gml, uint64_t index);
""")

ffibuilder.cdef("""
typedef void* (*gml_get_f)(gml_t *gml, uint64_t index);
""")

ffibuilder.cdef("""
typedef gml_t* (*gml_import_f)(gml_format_t format, void *src);
""")

ffibuilder.cdef("""
typedef int (*gml_export_f)(gml_t *gml, void *dst, gml_format_t format);
""")

ffibuilder.cdef("""
typedef int (*gml_export_new_entry_f)(
void *entry, 
void *dst, 
gml_format_t format);
""")

ffibuilder.cdef("""
typedef struct {
uint8_t scheme;
gml_init_f gml_init;
gml_free_f gml_free;
gml_insert_f gml_insert;
gml_remove_f gml_remove;
gml_get_f gml_get;
gml_import_f gml_import;
gml_export_f gml_export;
gml_export_new_entry_f gml_export_new_entry;
} gml_handle_t;
""")

ffibuilder.cdef("""
typedef int (*gml_cmp_entries_f)(void *entry1, void *entry2);
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
int gml_insert(gml_t *gml, void *entry);
""")

ffibuilder.cdef("""
int gml_remove(gml_t *gml, uint64_t index);
""")

ffibuilder.cdef("""
void* gml_get(gml_t *gml, uint64_t index);
""")

ffibuilder.cdef("""
gml_t* gml_import(
uint8_t code, 
gml_format_t format, 
void *source);
""")

ffibuilder.cdef("""
int gml_export(gml_t *gml, void *dst, gml_format_t format);
""")

ffibuilder.cdef("""
int gml_export_new_entry(uint8_t scheme, void *entry, void *dst, 
gml_format_t format);
""")

ffibuilder.cdef("""
int gml_compare_entries(
int *eq, 
void *entry1, 
void *entry2, 
gml_cmp_entries_f cmp);
""")

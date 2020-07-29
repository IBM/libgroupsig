# file "exim_build.py"

from common_build import ffibuilder

# Define data types

ffibuilder.cdef("""
typedef enum {
EXIM_FORMAT_FILE_NULL,
EXIM_FORMAT_FILE_NULL_B64,
EXIM_FORMAT_STRING_NULL_B64,
EXIM_FORMAT_MESSAGE_NULL,
EXIM_FORMAT_MESSAGE_NULL_B64,
EXIM_FORMAT_BYTEARRAY_NULL,
} exim_format_t;
""")

ffibuilder.cdef("""
typedef struct exim_handle_t exim_handle_t;
""")

ffibuilder.cdef("""
typedef struct exim_t exim_t;
""")

ffibuilder.cdef("""               
typedef int (*exim_get_size_bytearray_null_f)(exim_t* obj);
""")

ffibuilder.cdef("""
typedef int (*exim_export_bytearray_fd_f)(exim_t* obj, FILE* fd);
""")

ffibuilder.cdef("""
typedef int (*exim_import_bytearray_fd_f)(FILE *fd, exim_t* obj);
""")

ffibuilder.cdef("""
struct exim_handle_t {
exim_get_size_bytearray_null_f get_size_bytearray_null;
exim_export_bytearray_fd_f export_bytearray_fd;
exim_import_bytearray_fd_f import_bytearray_fd;
};
""")

ffibuilder.cdef("""               
struct exim_t {
  void *eximable;
  exim_handle_t *funcs;
};
""")

ffibuilder.cdef("""
int exim_get_size_in_format(exim_t *obj, exim_format_t format);
""")

ffibuilder.cdef("""               
int exim_export(exim_t* obj, exim_format_t format, void *dst);
""")

ffibuilder.cdef("""
int exim_import(exim_format_t format, void *source, exim_t* obj);
""")

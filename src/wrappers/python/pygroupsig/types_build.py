# file "types_build.py"

from pygroupsig.common_build import ffibuilder

# Define data types
#extern log_t logger;

ffibuilder.cdef("""
#define IOK 0
""")

ffibuilder.cdef("""
#define IERROR 1
""")

ffibuilder.cdef("""
#define IFAIL 2
""")

ffibuilder.cdef("""
#define IEXISTS 3
""")

ffibuilder.cdef("""
typedef unsigned char byte_t;
""")

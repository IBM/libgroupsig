#from skbuild import setup  # This line replaces 'from setuptools import setup'
from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="pygroupsig",
    version="1.0.0",
    author="Jesus Diaz Vico",
    author_email="jdv@zurich.ibm.com",
    description="A Python wrapper for libgroupsig",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/IBM/libgroupsig.git",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
	"Operating System :: OS Independent",
    ],
    package_dir={'pygroupsig': 'pygroupsig'},
    packages=['pygroupsig'],
    python_requires='>=3',
    setup_requires=["cffi"],
    cffi_modules=["pygroupsig/libgroupsig_build.py:ffibuilder"],
    install_requires=["cffi", "path.py"],
    test_suite="nose.collector",
    tests_require=["nose"],
)

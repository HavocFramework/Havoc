HCL Config Language Toolkit
===========================

HCL is a toolkit for creating structured configuration languages that are both
human- and machine-friendly, for use with command-line tools, servers, etc.

HCL has both a native syntax, intended to be pleasant to read and write for
humans, and a JSON-based variant that is easier for machines to generate and
parse. The native syntax is inspired by libucl_, `nginx configuration`_, and
others.

It includes an expression syntax that allows basic inline computation and, with
support from the calling application, use of variables and functions for more
dynamic configuration languages.

HCL provides a set of constructs that can be used by a calling application to
construct a configuration language. The application defines which argument
names and nested block types are expected, and HCL parses the configuration
file, verifies that it conforms to the expected structure, and returns
high-level objects that the application can use for further processing.

At present, HCL is primarily intended for use in applications written in Go_,
via its library API.

.. toctree::
   :maxdepth: 1
   :caption: Contents:

   intro
   go
   language_design

.. _libucl: https://github.com/vstakhov/libucl
.. _`nginx configuration`: http://nginx.org/en/docs/beginners_guide.html#conf_structure
.. _Go: https://golang.org/

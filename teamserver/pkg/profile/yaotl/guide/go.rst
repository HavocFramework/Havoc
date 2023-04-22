Using HCL in a Go application
=============================

HCL is itself written in Go_ and currently it is primarily intended for use as
a library within other Go programs.

This section describes a number of different ways HCL can be used to define
and process a configuration language within a Go program. For simple situations,
HCL can decode directly into Go ``struct`` values in a similar way as encoding
packages such as ``encoding/json`` and ``encoding/xml``.

The HCL Go API also offers some alternative approaches however, for processing
languages that may be more complex or that include portions whose expected
structure cannot be determined until runtime.

The following sections give an overview of different ways HCL can be used in
a Go program.

.. toctree::
   :maxdepth: 1
   :caption: Sub-sections:

   go_parsing
   go_diagnostics
   go_decoding_gohcl
   go_decoding_hcldec
   go_expression_eval
   go_decoding_lowlevel
   go_patterns

.. _Go: https://golang.org/

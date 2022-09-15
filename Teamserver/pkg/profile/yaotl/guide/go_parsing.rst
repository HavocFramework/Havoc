.. _go-parsing:

Parsing HCL Input
=================

The first step in processing HCL input provided by a user is to parse it.
Parsing turns the raw bytes from an input file into a higher-level
representation of the arguments and blocks, ready to be *decoded* into an
application-specific form.

The main entry point into HCL parsing is :go:pkg:`hclparse`, which provides
:go:type:`hclparse.Parser`:

.. code-block:: go

  parser := hclparse.NewParser()
  f, diags := parser.ParseHCLFile("server.conf")

Variable ``f`` is then a pointer to an :go:type:`hcl.File`, which is an
opaque abstract representation of the file, ready to be decoded.

Variable ``diags`` describes any errors or warnings that were encountered
during processing; HCL conventionally uses this in place of the usual ``error``
return value in Go, to allow returning a mixture of multiple errors and
warnings together with enough information to present good error messages to the
user. We'll cover this in more detail in the next section,
:ref:`go-diagnostics`.

.. go:package:: hclparse

Package ``hclparse``
--------------------

.. go:type:: Parser

  .. go:function:: func NewParser() *Parser

      Constructs a new parser object. Each parser contains a cache of files
      that have already been read, so repeated calls to load the same file
      will return the same object.

  .. go:function:: func (*Parser) ParseHCL(src []byte, filename string) (*hcl.File, hcl.Diagnostics)

     Parse the given source code as HCL native syntax, saving the result into
     the parser's file cache under the given filename.

  .. go:function:: func (*Parser) ParseHCLFile(filename string) (*hcl.File, hcl.Diagnostics)

     Parse the contents of the given file as HCL native syntax. This is a
     convenience wrapper around ParseHCL that first reads the file into memory.

  .. go:function:: func (*Parser) ParseJSON(src []byte, filename string) (*hcl.File, hcl.Diagnostics)

     Parse the given source code as JSON syntax, saving the result into
     the parser's file cache under the given filename.

  .. go:function:: func (*Parser) ParseJSONFile(filename string) (*hcl.File, hcl.Diagnostics)

     Parse the contents of the given file as JSON syntax. This is a
     convenience wrapper around ParseJSON that first reads the file into memory.

The above list just highlights the main functions in this package.
For full documentation, see
`the hclparse godoc <https://godoc.org/Havoc/pkg/profile/yaotl/hclparse>`_.

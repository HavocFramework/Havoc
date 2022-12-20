.. go:package:: gohcl

.. _go-decoding-gohcl:

Decoding Into Native Go Values
==============================

The most straightforward way to access the content of an HCL file is to
decode into native Go values using ``reflect``, similar to the technique used
by packages like ``encoding/json`` and ``encoding/xml``.

Package ``gohcl`` provides functions for this sort of decoding. Function
``DecodeBody`` attempts to extract values from an HCL *body* and write them
into a Go value given as a pointer:

.. code-block:: go

   type ServiceConfig struct {
     Type       string `hcl:"type,label"`
     Name       string `hcl:"name,label"`
     ListenAddr string `hcl:"listen_addr"`
   }
   type Config struct {
     IOMode   string          `hcl:"io_mode"`
     Services []ServiceConfig `hcl:"service,block"`
   }

   var c Config
   moreDiags := gohcl.DecodeBody(f.Body, nil, &c)
   diags = append(diags, moreDiags...)

The above example decodes the *root body* of a file ``f``, presumably loaded
previously using a parser, into the variable ``c``. The field labels within
the struct types imply the schema of the expected language, which is a cut-down
version of the hypothetical language we showed in :ref:`intro`.

The struct field labels consist of two comma-separated values. The first is
the name of the corresponding argument or block type as it will appear in
the input file, and the second is the type of element being named. If the
second value is omitted, it defaults to ``attr``, requesting an attribute.

Nested blocks are represented by a struct or a slice of that struct, and the
special element type ``label`` within that struct declares that each instance
of that block type must be followed by one or more block labels. In the above
example, the ``service`` block type is defined to require two labels, named
``type`` and ``name``. For label fields in particular, the given name is used
only to refer to the particular label in error messages when the wrong number
of labels is used.

By default, all declared attributes and blocks are considered to be required.
An optional value is indicated by making its field have a pointer type, in
which case ``nil`` is written to indicate the absense of the argument.

The sections below discuss some additional decoding use-cases. For full details
on the `gohcl` package, see
`the godoc reference <https://godoc.org/Havoc/pkg/profile/yaotl/gohcl>`_.

.. _go-decoding-gohcl-evalcontext:

Variables and Functions
-----------------------

By default, arguments given in the configuration may use only literal values
and the built in expression language operators, such as arithmetic.

The second argument to ``gohcl.DecodeBody``, shown as ``nil`` in the previous
example, allows the calling application to additionally offer variables and
functions for use in expressions. Its value is a pointer to an
``hcl.EvalContext``, which will be covered in more detail in the later section
:ref:`go-expression-eval`. For now, a simple example of making the id of the
current process available as a single variable called ``pid``:

.. code-block:: go

   type Context struct {
       Pid string
   }
   ctx := gohcl.EvalContext(&Context{
       Pid: os.Getpid()
   })
   var c Config
   moreDiags := gohcl.DecodeBody(f.Body, ctx, &c)
   diags = append(diags, moreDiags...)

``gohcl.EvalContext`` constructs an expression evaluation context from a Go
struct value, making the fields available as variables and the methods
available as functions, after transforming the field and method names such
that each word (starting with an uppercase letter) is all lowercase and
separated by underscores.

.. code-block:: hcl

   name = "example-program (${pid})"

Partial Decoding
----------------

In the examples so far, we've extracted the content from the entire input file
in a single call to ``DecodeBody``. This is sufficient for many simple
situations, but sometimes different parts of the file must be evaluated
separately. For example:

* If different parts of the file must be evaluated with different variables
  or functions available.

* If the result of evaluating one part of the file is used to set variables
  or functions in another part of the file.

There are several ways to perform partial decoding with ``gohcl``, all of
which involve decoding into HCL's own types, such as ``hcl.Body``.

The most general approach is to declare an additional struct field of type
``hcl.Body``, with the special field tag type ``remain``:

.. code-block:: go

   type ServiceConfig struct {
     Type       string   `hcl:"type,label"`
     Name       string   `hcl:"name,label"`
     ListenAddr string   `hcl:"listen_addr"`
     Remain     hcl.Body `hcl:",remain"`
   }

When a ``remain`` field is present, any element of the input body that is
not matched is retained in a body saved into that field, which can then be
decoded in a later call, potentially with a different evaluation context.

Another option is to decode an attribute into a value of type `hcl.Expression`,
which can then be evaluated separately as described in
:ref:`expression-eval`.

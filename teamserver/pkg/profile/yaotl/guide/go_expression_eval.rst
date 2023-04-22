.. _go-expression-eval:

Expression Evaluation
=====================

Each argument attribute in a configuration file is interpreted as an
expression. In the HCL native syntax, certain basic expression functionality
is always available, such as arithmetic and template strings, and the calling
application can extend this by making available specific variables and/or
functions via an *evaluation context*.

We saw in :ref:`go-decoding-gohcl` and :ref:`go-decoding-hcldec` some basic
examples of populating an evaluation context to make a variable available.
This section will look more closely at the ``hcl.EvalContext`` type and how
HCL expression evaluation behaves in different cases.

This section does not discuss in detail the expression syntax itself. For more
information on that, see the HCL Native Syntax specification.

.. go:currentpackage:: hcl

.. go:type:: EvalContext

   ``hcl.EvalContext`` is the type used to describe the variables and functions
   available during expression evaluation, if any. Its usage is described in
   the following sections.

Defining Variables
------------------

As we saw in :ref:`go-decoding-hcldec`, HCL represents values using an
underlying library called :go:pkg:`cty`. When defining variables, their values
must be given as :go:type:`cty.Value` values.

A full description of the types and value constructors in :go:pkg:`cty` is
in `the reference documentation <https://github.com/zclconf/go-cty/blob/master/docs/types.md>`_.
Variables in HCL are defined by assigning values into a map from string names
to :go:type:`cty.Value`:

.. code-block:: go

   ctx := &hcl.EvalContext{
        Variables: map[string]cty.Value{
            "name": cty.StringVal("Ermintrude"),
            "age":  cty.NumberIntVal(32),
        },
   }

If this evaluation context were passed to one of the evaluation functions we
saw in previous sections, the user would be able to refer to these variable
names in any argument expression appearing in the evaluated portion of
configuration:

.. code-block:: hcl

   message = "${name} is ${age} ${age == 1 ? "year" : "years"} old!"

If you place ``cty``'s *object* values in the evaluation context, then their
attributes can be referenced using the HCL attribute syntax, allowing for more
complex structures:

.. code-block:: go

   ctx := &hcl.EvalContext{
        Variables: map[string]cty.Value{
            "path": cty.ObjectVal(map[string]cty.Value{
                "root":    cty.StringVal(rootDir),
                "module":  cty.StringVal(moduleDir),
                "current": cty.StringVal(currentDir),
            }),
        },
   }

.. code-block:: hcl

   source_file = "${path.module}/foo.txt"

.. _go-expression-funcs:

Defining Functions
------------------

Custom functions can be defined by you application to allow users of its
language to transform data in application-specific ways. The underlying
function mechanism is also provided by :go:pkg:`cty`, allowing you to define
the arguments a given function expects, what value type it will return for
given argument types, etc. The full functions model is described in the
``cty`` documentation section
`Functions System <https://github.com/zclconf/go-cty/blob/master/docs/functions.md>`_.

There are `a number of "standard library" functions <https://godoc.org/github.com/apparentlymart/go-cty/cty/function/stdlib>`_
available in a ``stdlib`` package within the :go:pkg:`cty` repository, avoiding
the need for each application to re-implement basic functions for string
manipulation, list manipulation, etc. It also includes function-shaped versions
of several operations that are native operators in HCL, which should generally
*not* be exposed as functions in HCL-based configuration formats to avoid user
confusion.

You can define functions in the ``Functions`` field of :go:type:`hcl.EvalContext`:

.. code-block:: go

   ctx := &hcl.EvalContext{
        Variables: map[string]cty.Value{
            "name": cty.StringVal("Ermintrude"),
        },
        Functions: map[string]function.Function{
            "upper":  stdlib.UpperFunc,
            "lower":  stdlib.LowerFunc,
            "min":    stdlib.MinFunc,
            "max":    stdlib.MaxFunc,
            "strlen": stdlib.StrlenFunc,
            "substr": stdlib.SubstrFunc,
        },
   }

If this evaluation context were passed to one of the evaluation functions we
saw in previous sections, the user would be able to call any of these functions
in any argument expression appearing in the evaluated portion of configuration:

.. code-block:: hcl

   message = "HELLO, ${upper(name)}!"

Expression Evaluation Modes
---------------------------

HCL uses a different expression evaluation mode depending on the evaluation
context provided. In HCL native syntax, evaluation modes are used to provide
more relevant error messages. In JSON syntax, which embeds the native
expression syntax in strings using "template" syntax, the evaluation mode
determines whether strings are evaluated as templates at all.

If the given :go:type:`hcl.EvalContext` is ``nil``, native syntax expressions
will react to users attempting to refer to variables or functions by producing
errors indicating that these features are not available at all, rather than
by saying that the specific variable or function does not exist. JSON syntax
strings will not be evaluated as templates *at all* in this mode, making them
function as literal strings.

If the evaluation context is non-``nil`` but either ``Variables`` or
``Functions`` within it is ``nil``, native syntax will similarly produce
"not supported" error messages. JSON syntax strings *will* parse templates
in this case, but can also generate "not supported" messages if e.g. the
user accesses a variable when the variables map is ``nil``.

If neither map is ``nil``, HCL assumes that both variables and functions are
supported and will instead produce error messages stating that the specific
variable or function accessed by the user is not defined.

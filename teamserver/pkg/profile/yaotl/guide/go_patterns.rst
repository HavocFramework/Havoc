Design Patterns for Complex Systems
===================================

In previous sections we've seen an overview of some different ways an
application can decode a language its has defined in terms of the HCL grammar.
For many applications, those mechanisms are sufficient. However, there are
some more complex situations that can benefit from some additional techniques.
This section lists a few of these situations and ways to use the HCL API to
accommodate them.

.. _go-interdep-blocks:

Interdependent Blocks
---------------------

In some configuration languages, the variables available for use in one
configuration block depend on values defined in other blocks.

For example, in Terraform many of the top-level constructs are also implicitly
definitions of values that are available for use in expressions elsewhere:

.. code-block:: hcl

   variable "network_numbers" {
     type = list(number)
   }

   variable "base_network_addr" {
     type    = string
     default = "10.0.0.0/8"
   }

   locals {
     network_blocks = {
       for x in var.number:
       x => cidrsubnet(var.base_network_addr, 8, x)
     }
   }

   resource "cloud_subnet" "example" {
     for_each = local.network_blocks

     cidr_block = each.value
   }

   output "subnet_ids" {
     value = cloud_subnet.example[*].id
   }

In this example, the ``variable "network_numbers"`` block makes
``var.network_numbers`` available to expressions, the
``resource "cloud_subnet" "example"`` block makes ``cloud_subnet.example``
available, etc.

Terraform achieves this by decoding the top-level structure in isolation to
start. You can do this either using the low-level API or using :go:pkg:`gohcl`
with :go:type:`hcl.Body` fields tagged as "remain".

Once you have a separate body for each top-level block, you can inspect each
of the attribute expressions inside using the ``Variables`` method on
:go:type:`hcl.Expression`, or the ``Variables`` function from package
:go:pkg:`hcldec` if you will eventually use its higher-level API to decode as
Terraform does.

The detected variable references can then be used to construct a dependency
graph between the blocks, and then perform a
`topological sort <https://en.wikipedia.org/wiki/Topological_sorting>`_ to
determine the correct order to evaluate each block's contents so that values
will always be available before they are needed.

Since :go:pkg:`cty` values are immutable, it is not convenient to directly
change values in a :go:type:`hcl.EvalContext` during this gradual evaluation,
so instead construct a specialized data structure that has a separate value
per object and construct an evaluation context from that each time a new
value becomes available.

Using :go:pkg:`hcldec` to evaluate block bodies is particularly convenient in
this scenario because it produces :go:type:`cty.Value` results which can then
just be directly incorporated into the evaluation context.

Distributed Systems
-------------------

Distributed systems cause a number of extra challenges, and configuration
management is rarely the worst of these. However, there are some specific
considerations for using HCL-based configuration in distributed systems.

For the sake of this section, we are concerned with distributed systems where
at least two separate components both depend on the content of HCL-based
configuration files. Real-world examples include the following:

* **HashiCorp Nomad** loads configuration (job specifications) in its servers
  but also needs these results in its clients and in its various driver plugins.

* **HashiCorp Terraform** parses configuration in Terraform Core but can write
  a partially-evaluated execution plan to disk and continue evaluation in a
  separate process later. It must also pass configuration values into provider
  plugins.

Broadly speaking, there are two approaches to allowing configuration to be
accessed in multiple subsystems, which the following subsections will discuss
separately.

Ahead-of-time Evaluation
^^^^^^^^^^^^^^^^^^^^^^^^

Ahead-of-time evaluation is the simplest path, with the configuration files
being entirely evaluated on entry to the system, and then only the resulting
*constant values* being passed between subsystems.

This approach is relatively straightforward because the resulting
:go:type:`cty.Value` results can be losslessly serialized as either JSON or
msgpack as long as all system components agree on the expected value types.
Aside from passing these values around "on the wire", parsing and decoding of
configuration proceeds as normal.

Both Nomad and Terraform use this approach for interacting with *plugins*,
because the plugins themselves are written by various different teams that do
not coordinate closely, and so doing all expression evaluation in the core
subsystems ensures consistency between plugins and simplifies plugin development.

In both applications, the plugin is expected to describe (using an
application-specific protocol) the schema it expects for each element of
configuration it is responsible for, allowing the core subsystems to perform
decoding on the plugin's behalf and pass a value that is guaranteed to conform
to the schema.

Gradual Evaluation
^^^^^^^^^^^^^^^^^^

Although ahead-of-time evaluation is relatively straightforward, it has the
significant disadvantage that all data available for access via variables or
functions must be known by whichever subsystem performs that initial
evaluation.

For example, in Terraform, the "plan" subcommand is responsible for evaluating
the configuration and presenting to the user an execution plan for approval, but
certain values in that plan cannot be determined until the plan is already
being applied, since the specific values used depend on remote API decisions
such as the allocation of opaque id strings for objects.

In Terraform's case, both the creation of the plan and the eventual apply
of that plan *both* entail evaluating configuration, with the apply step
having a more complete set of input values and thus producing a more complete
result. However, this means that Terraform must somehow make the expressions
from the original input configuration available to the separate process that
applies the generated plan.

Good usability requires error and warning messages that are able to refer back
to specific sections of the input configuration as context for the reported
problem, and the best way to achieve this in a distributed system doing
gradual evaluation is to send the configuration *source code* between
subsystems. This is generally the most compact representation that retains
source location information, and will avoid any inconsistency caused by
introducing another intermediate serialization.

In Terraform's, for example, the serialized plan incorporates both the data
structure describing the partial evaluation results from the plan phase and
the original configuration files that produced those results, which can then
be re-evalauated during the apply step.

In a gradual evaluation scenario, the application should verify correctness of
the input configuration as completely as possible at each state. To help with
this, :go:pkg:`cty` has the concept of
`unknown values <https://github.com/zclconf/go-cty/blob/master/docs/concepts.md#unknown-values-and-the-dynamic-pseudo-type>`_,
which can stand in for values the application does not yet know while still
retaining correct type information. HCL expression evaluation reacts to unknown
values by performing type checking but then returning another unknown value,
causing the unknowns to propagate through expressions automatically.

.. code-block:: go

   ctx := &hcl.EvalContext{
        Variables: map[string]cty.Value{
            "name": cty.UnknownVal(cty.String),
            "age":  cty.UnknownVal(cty.Number),
        },
   }
   val, moreDiags := expr.Value(ctx)
   diags = append(diags, moreDiags...)

Each time an expression is re-evaluated with additional information, fewer of
the input values will be unknown and thus more of the result will be known.
Eventually the application should evaluate the expressions with no unknown
values at all, which then guarantees that the result will also be wholly-known.

Static References, Calls, Lists, and Maps
-----------------------------------------

In most cases, we care more about the final result value of an expression than
how that value was obtained. A particular list argument, for example, might
be defined by the user via a tuple constructor, by a `for` expression, or by
assigning the value of a variable that has a suitable list type.

In some special cases, the structure of the expression is more important than
the result value, or an expression may not *have* a reasonable result value.
For example, in Terraform there are a few arguments that call for the user
to name another object by reference, rather than provide an object value:

.. code-block:: hcl

   resource "cloud_network" "example" {
     # ...
   }

   resource "cloud_subnet" "example" {
     cidr_block = "10.1.2.0/24"

     depends_on = [
       cloud_network.example,
     ]
   }

The ``depends_on`` argument in the second ``resource`` block *appears* as an
expression that would construct a single-element tuple containing an object
representation of the first resource block. However, Terraform uses this
expression to construct its dependency graph, and so it needs to see
specifically that this expression refers to ``cloud_network.example``, rather
than determine a result value for it.

HCL offers a number of "static analysis" functions to help with this sort of
situation. These all live in the :go:pkg:`hcl` package, and each one imposes
a particular requirement on the syntax tree of the expression it is given,
and returns a result derived from that if the expression conforms to that
requirement.

.. go:currentpackage:: hcl

.. go:function:: func ExprAsKeyword(expr Expression) string

   This function attempts to interpret the given expression as a single keyword,
   returning that keyword as a string if possible.

   A "keyword" for the purposes of this function is an expression that can be
   understood as a valid single identifier. For example, the simple variable
   reference ``foo`` can be interpreted as a keyword, while ``foo.bar``
   cannot.

   As a special case, the language-level keywords ``true``, ``false``, and
   ``null`` are also considered to be valid keywords, allowing the calling
   application to disregard their usual meaning.

   If the given expression cannot be reduced to a single keyword, the result
   is an empty string. Since an empty string is never a valid keyword, this
   result unambiguously signals failure.

.. go:function:: func AbsTraversalForExpr(expr Expression) (Traversal, Diagnostics)

   This is a generalization of ``ExprAsKeyword`` that will accept anything that
   can be interpreted as a *traversal*, which is a variable name followed by
   zero or more attribute access or index operators with constant operands.

   For example, all of ``foo``, ``foo.bar`` and ``foo[0]`` are valid
   traversals, but ``foo[bar]`` is not, because the ``bar`` index is not
   constant.

   This is the function that Terraform uses to interpret the items within the
   ``depends_on`` sequence in our example above.

   As with ``ExprAsKeyword``, this function has a special case that the
   keywords ``true``, ``false``, and ``null`` will be accepted as if they were
   variable names by this function, allowing ``null.foo`` to be interpreted
   as a traversal even though it would be invalid if evaluated.

   If error diagnostics are returned, the traversal result is invalid and
   should not be used.

.. go:function:: func RelTraversalForExpr(expr Expression) (Traversal, Diagnostics)

   This is very similar to ``AbsTraversalForExpr``, but the result is a
   *relative* traversal, which is one whose first name is considered to be
   an attribute of some other (implied) object.

   The processing rules are identical to ``AbsTraversalForExpr``, with the
   only exception being that the first element of the returned traversal is
   marked as being an attribute, rather than as a root variable.

.. go:function:: func ExprList(expr Expression) ([]Expression, Diagnostics)

   This function requires that the given expression be a tuple constructor,
   and if so returns a slice of the element expressions in that constructor.
   Applications can then perform further static analysis on these, or evaluate
   them as normal.

   If error diagnostics are returned, the result is invalid and should not be
   used.

   This is the fucntion that Terraform uses to interpret the expression
   assigned to ``depends_on`` in our example above, then in turn using
   ``AbsTraversalForExpr`` on each enclosed expression.

.. go:function:: func ExprMap(expr Expression) ([]KeyValuePair, Diagnostics)

   This function requires that the given expression be an object constructor,
   and if so returns a slice of the element key/value pairs in that constructor.
   Applications can then perform further static analysis on these, or evaluate
   them as normal.

   If error diagnostics are returned, the result is invalid and should not be
   used.

.. go:function:: func ExprCall(expr Expression) (*StaticCall, Diagnostics)

   This function requires that the given expression be a function call, and
   if so returns an object describing the name of the called function and
   expression objects representing the call arguments.

   If error diagnostics are returned, the result is invalid and should not be
   used.

The ``Variables`` method on :go:type:`hcl.Expression` is also considered to be
a "static analysis" helper, but is built in as a fundamental feature because
analysis of referenced variables is often important for static validation and
for implementing interdependent blocks as we saw in the section above.


.. _go-decoding-lowlevel:

Advanced Decoding With The Low-level API
========================================

In previous sections we've discussed :go:pkg:`gohcl` and :go:pkg:`hcldec`,
which both deal with decoding of HCL bodies and the expressions within them
using a high-level description of the expected configuration schema.
Both of these packages are implemented in terms of HCL's low-level decoding
interfaces, which we will explore in this section.

HCL decoding in the low-level API has two distinct phases:

* Structural decoding: analyzing the arguments and nested blocks present in a
  particular body.

* Expression evaluation: obtaining final values for each argument expression
  found during structural decoding.

The low-level API gives the calling application full control over when each
body is decoded and when each expression is evaluated, allowing for more
complex configuration formats where e.g. different variables are available in
different contexts, or perhaps expressions within one block can refer to
values defined in another block.

The low-level API also gives more detailed access to source location
information for decoded elements, and so may be desirable for applications that
do a lot of additional validation of decoded data where more specific source
locations lead to better diagnostic messages.

Since all of the decoding mechanisms work with the same :go:type:`hcl.Body`
type, it is fine and expected to mix them within an application to get access
to the more detailed information where needed while using the higher-level APIs
for the more straightforward portions of a configuration language.

The following subsections will give an overview of the low-level API. For full
details, see `the godoc reference <https://godoc.org/Havoc/pkg/profile/yaotl/hcl>`_.

Structural Decoding
-------------------

As seen in prior sections, :go:type:`hcl.Body` is an opaque representation of
the arguments and child blocks at a particular nesting level. An HCL file has
a root body containing the top-level elements, and then each nested block has
its own body presenting its own content.

:go:type:`hcl.Body` is a Go interface whose methods serve as the structural
decoding API:

.. go:currentpackage:: hcl

.. go:type:: Body

   Represents the structural elements at a particular nesting level.

   .. go:function:: func (b Body) Content(schema *BodySchema) (*BodyContent, Diagnostics)

      Decode the content from the receiving body using the given schema. The
      schema is considered exhaustive of all content within the body, and so
      any elements not covered by the schema will generate error diagnostics.

   .. go:function:: func (b Body) PartialContent(schema *BodySchema) (*BodyContent, Body, Diagnostics)

      Similar to `Content`, but allows for additional arguments and block types
      that are not described in the given schema. The additional body return
      value is a special body that contains only the *remaining* elements, after
      extraction of the ones covered by the schema. This returned body can be
      used to decode the remaining content elsewhere in the calling program.

   .. go:function:: func (b Body) JustAttributes() (Attributes, Diagnostics)

      Decode the content from the receving body in a special *attributes-only*
      mode, allowing the calling application to enumerate the arguments given
      inside the body without needing to predict them in schema.

      When this method is used, a body can be treated somewhat like a map
      expression, but it still has a rigid structure where the arguments must
      be given directly with no expression evaluation. This is an advantage for
      declarations that must themselves be resolved before expression
      evaluation is possible.

      If the body contains any blocks, error diagnostics are returned. JSON
      syntax relies on schema to distinguish arguments from nested blocks, and
      so a JSON body in attributes-only mode will treat all JSON object
      properties as arguments.

   .. go:function:: func (b Body) MissingItemRange() Range

      Returns a source range that points to where an absent required item in
      the body might be placed. This is a "best effort" sort of thing, required
      only to be somewhere inside the receving body, as a way to give source
      location information for a "missing required argument" sort of error.

The main content-decoding methods each require a :go:type:`hcl.BodySchema`
object describing the expected content. The fields of this type describe the
expected arguments and nested block types respectively:

.. code-block:: go

   schema := &hcl.BodySchema{
       Attributes: []hcl.AttributeSchema{
           {
               Name:     "io_mode",
               Required: false,
           },
       },
       Blocks: []hcl.BlockHeaderSchema{
           {
               Type:       "service",
               LabelNames: []string{"type", "name"},
           },
       },
   }
   content, moreDiags := body.Content(schema)
   diags = append(diags, moreDiags...)

:go:type:`hcl.BodyContent` is the result of both ``Content`` and
``PartialContent``, giving the actual attributes and nested blocks that were
found. Since arguments are uniquely named within a body and unordered, they
are returned as a map. Nested blocks are ordered and may have many instances
of a given type, so they are returned all together in a single slice for
further interpretation by the caller.

Unlike the two higher-level approaches, the low-level API *always* works only
with one nesting level at a time. Decoding a nested block returns the "header"
for that block, giving its type and label values, but its body remains an
:go:type:`hcl.Body` for later decoding.

Each returned attribute corresponds to one of the arguments in the body, and
it has an :go:type:`hcl.Expression` object that can be used to obtain a value
for the argument during expression evaluation, as described in the next
section.

Expression Evaluation
---------------------

Expression evaluation *in general* has its own section, imaginitively titled
:ref:`go-expression-eval`, so this section will focus only on how it is
achieved in the low-level API.

All expression evaluation in the low-level API starts with an
:go:type:`hcl.Expression` object. This is another interface type, with various
implementations depending on the expression type and the syntax it was parsed
from.

.. go:currentpackage:: hcl

.. go:type:: Expression

   Represents a unevaluated single expression.

   .. go:function:: func (e Expression) Value(ctx *EvalContext) (cty.Value, Diagnostics)

      Evaluates the receiving expression in the given evaluation context. The
      result is a :go:type:`cty.Value` representing the result value, along
      with any diagnostics that were raised during evaluation.

      If the diagnostics contains errors, the value may be incomplete or
      invalid and should either be discarded altogether or used with care for
      analysis.

   .. go:function:: func (e Expression) Variables() []Traversal

      Returns information about any nested expressions that access variables
      from the *global* evaluation context. Does not include references to
      temporary local variables, such as those generated by a
      "``for`` expression".

   .. go:function:: func (e Expression) Range() Range

      Returns the source range for the entire expression. This can be useful
      when generating application-specific diagnostic messages, such as
      value validation errors.

   .. go:function:: func (e Expression) StartRange() Range

      Similar to ``Range``, but if the expression is complex, such as a tuple
      or object constructor, may indicate only the opening tokens for the
      construct to avoid creating an overwhelming source code snippet.

      This should be used in diagnostic messages only in situations where the
      error is clearly with the construct itself and not with the overall
      expression. For example, a type error indicating that a tuple was not
      expected might use ``StartRange`` to draw attention to the beginning
      of a tuple constructor, without highlighting the entire expression.

Method ``Value`` is the primary API for expressions, and takes the same kind
of evaluation context object described in :ref:`go-expression-eval`.

.. code-block:: go

   ctx := &hcl.EvalContext{
        Variables: map[string]cty.Value{
            "name": cty.StringVal("Ermintrude"),
            "age":  cty.NumberIntVal(32),
        },
   }
   val, moreDiags := expr.Value(ctx)
   diags = append(diags, moreDiags...)

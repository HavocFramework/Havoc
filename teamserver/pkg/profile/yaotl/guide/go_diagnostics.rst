.. _go-diagnostics:

Diagnostic Messages
===================

An important concern for any machine language intended for human authoring is
to produce good error messages when the input is somehow invalid, or has
other problems.

HCL uses *diagnostics* to describe problems in an end-user-oriented manner,
such that the calling application can render helpful error or warning messages.
The word "diagnostic" is a general term that covers both errors and warnings,
where errors are problems that prevent complete processing while warnings are
possible concerns that do not block processing.

HCL deviates from usual Go API practice by returning its own ``hcl.Diagnostics``
type, instead of Go's own ``error`` type. This allows functions to return
warnings without accompanying errors while not violating the usual expectation
that the absense of errors is indicated by a nil ``error``.

In order to easily accumulate and return multiple diagnostics at once, the
usual pattern for functions returning diagnostics is to gather them in a
local variable and then return it at the end of the function, or possibly
earlier if the function cannot continue due to the problems.

.. code-block:: go

  func returningDiagnosticsExample() hcl.Diagnostics {
      var diags hcl.Diagnostics

      // ...

      // Call a function that may itself produce diagnostics.
      f, moreDiags := parser.LoadHCLFile("example.conf")
      // always append, in case warnings are present
      diags = append(diags, moreDiags...)
      if diags.HasErrors() {
        // If we can't safely continue in the presence of errors here, we
        // can optionally return early.
        return diags
      }

      // ...

      return diags
  }

A common variant of the above pattern is calling another diagnostics-generating
function in a loop, using ``continue`` to begin the next iteration when errors
are detected, but still completing all iterations and returning the union of
all of the problems encountered along the way.

In :ref:`go-parsing`, we saw that the parser can generate diagnostics which
are related to syntax problems within the loaded file. Further steps to decode
content from the loaded file can also generate diagnostics related to *semantic*
problems within the file, such as invalid expressions or type mismatches, and
so a program using HCL will generally need to accumulate diagnostics across
these various steps and then render them in the application UI somehow.

Rendering Diagnostics in the UI
-------------------------------

The best way to render diagnostics to an end-user will depend a lot on the
type of application: they might be printed into a terminal, written into a
log for later review, or even shown in a GUI.

HCL leaves the responsibility for rendering diagnostics to the calling
application, but since rendering to a terminal is a common case for command-line
tools, the `hcl` package contains a default implementation of this in the
form of a "diagnostic text writer":

.. code-block:: go

   wr := hcl.NewDiagnosticTextWriter(
       os.Stdout,      // writer to send messages to
       parser.Files(), // the parser's file cache, for source snippets
       78,             // wrapping width
       true,           // generate colored/highlighted output
   )
   wr.WriteDiagnostics(diags)

This default implementation of diagnostic rendering includes relevant lines
of source code for context, like this:

::

  Error: Unsupported block type

    on example.tf line 4, in resource "aws_instance" "example":
     2: provisionr "local-exec" {

  Blocks of type "provisionr" are not expected here. Did you mean "provisioner"?

If the "color" flag is enabled, the severity will be additionally indicated by
a text color and the relevant portion of the source code snippet will be
underlined to draw further attention.


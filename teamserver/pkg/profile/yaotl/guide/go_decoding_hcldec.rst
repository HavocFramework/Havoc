.. go:package:: hcldec

.. _go-decoding-hcldec:

Decoding With Dynamic Schema
============================

In section :ref:`go-decoding-gohcl`, we saw the most straightforward way to
access the content from an HCL file, decoding directly into a Go value whose
type is known at application compile time.

For some applications, it is not possible to know the schema of the entire
configuration when the application is built. For example, `HashiCorp Terraform`_
uses HCL as the foundation of its configuration language, but parts of the
configuration are handled by plugins loaded dynamically at runtime, and so
the schemas for these portions cannot be encoded directly in the Terraform
source code.

HCL's ``hcldec`` package offers a different approach to decoding that allows
schemas to be created at runtime, and the result to be decoded into
dynamically-typed data structures.

The sections below are an overview of the main parts of package ``hcldec``.
For full details, see
`the package godoc <https://godoc.org/Havoc/pkg/profile/yaotl/hcldec>`_.

.. _`HashiCorp Terraform`: https://www.terraform.io/

Decoder Specification
---------------------

Whereas :go:pkg:`gohcl` infers the expected schema by using reflection against
the given value, ``hcldec`` obtains schema through a decoding *specification*,
which is a set of instructions for mapping HCL constructs onto a dynamic
data structure.

The ``hcldec`` package contains a number of different specifications, each
implementing :go:type:`hcldec.Spec` and having a ``Spec`` suffix on its name.
Each spec has two distinct functions:

* Adding zero or more validation constraints on the input configuration file.

* Producing a result value based on some elements from the input file.

The most common pattern is for the top-level spec to be a
:go:type:`hcldec.ObjectSpec` with nested specifications defining either blocks
or attributes, depending on whether the configuration file will be
block-structured or flat.

.. code-block:: go

  spec := hcldec.ObjectSpec{
      "io_mode": &hcldec.AttrSpec{
          Name: "io_mode",
          Type: cty.String,
      },
      "services": &hcldec.BlockMapSpec{
          TypeName:   "service",
          LabelNames: []string{"type", "name"},
          Nested:     hcldec.ObjectSpec{
              "listen_addr": &hcldec.AttrSpec{
                  Name:     "listen_addr",
                  Type:     cty.String,
                  Required: true,
              },
              "processes": &hcldec.BlockMapSpec{
                  TypeName:   "service",
                  LabelNames: []string{"name"},
                  Nested:     hcldec.ObjectSpec{
                      "command": &hcldec.AttrSpec{
                          Name:     "command",
                          Type:     cty.List(cty.String),
                          Required: true,
                      },
                  },
              },
          },
      },
  }
  val, moreDiags := hcldec.Decode(f.Body, spec, nil)
  diags = append(diags, moreDiags...)

The above specification expects a configuration shaped like our example in
:ref:`intro`, and calls for it to be decoded into a dynamic data structure
that would have the following shape if serialized to JSON:

.. code-block:: JSON

  {
    "io_mode": "async",
    "services": {
      "http": {
        "web_proxy": {
          "listen_addr": "127.0.0.1:8080",
          "processes": {
            "main": {
              "command": ["/usr/local/bin/awesome-app", "server"]
            },
            "mgmt": {
              "command": ["/usr/local/bin/awesome-app", "mgmt"]
            }
          }
        }
      }
    }
  }

.. go:package:: cty

Types and Values With ``cty``
-----------------------------

HCL's expression interpreter is implemented in terms of another library called
:go:pkg:`cty`, which provides a type system which HCL builds on and a robust
representation of dynamic values in that type system. You could think of
:go:pkg:`cty` as being a bit like Go's own :go:pkg:`reflect`, but for the
results of HCL expressions rather than Go programs.

The full details of this system can be found in
`its own repository <https://github.com/zclconf/go-cty>`_, but this section
will cover the most important highlights, because ``hcldec`` specifications
include :go:pkg:`cty` types (as seen in the above example) and its results are
:go:pkg:`cty` values.

``hcldec`` works directly with :go:pkg:`cty` — as opposed to converting values
directly into Go native types — because the functionality of the :go:pkg:`cty`
packages then allows further processing of those values without any loss of
fidelity or range. For example, :go:pkg:`cty` defines a JSON encoding of its
values that can be decoded losslessly as long as both sides agree on the value
type that is expected, which is a useful capability in systems where some sort
of RPC barrier separates the main program from its plugins.

Types are instances of :go:type:`cty.Type`, and are constructed from functions
and variables in :go:pkg:`cty` as shown in the above example, where the string
attributes are typed as ``cty.String``, which is a primitive type, and the list
attribute is typed as ``cty.List(cty.String)``, which constructs a new list
type with string elements.

Values are instances of :go:type:`cty.Value`, and can also be constructed from
functions in :go:pkg:`cty`, using the functions that include ``Val`` in their
names or using the operation methods available on :go:type:`cty.Value`.

In most cases you will eventually want to use the resulting data as native Go
types, to pass it to non-:go:pkg:`cty`-aware code. To do this, see the guides
on
`Converting between types <https://github.com/zclconf/go-cty/blob/master/docs/convert.md>`_
(staying within :go:pkg:`cty`) and
`Converting to and from native Go values <https://github.com/zclconf/go-cty/blob/master/docs/gocty.md>`_.

Partial Decoding
----------------

Because the ``hcldec`` result is always a value, the input is always entirely
processed in a single call, unlike with :go:pkg:`gohcl`.

However, both :go:pkg:`gohcl` and :go:pkg:`hcldec` take :go:type:`hcl.Body` as
the representation of input, and so it is possible and common to mix them both
in the same program.

A common situation is that :go:pkg:`gohcl` is used in the main program to
decode the top level of configuration, which then allows the main program to
determine which plugins need to be loaded to process the leaf portions of
configuration. In this case, the portions that will be interpreted by plugins
are retained as opaque :go:type:`hcl.Body` until the plugins have been loaded,
and then each plugin provides its :go:type:`hcldec.Spec` to allow decoding the
plugin-specific configuration into a :go:type:`cty.Value` which be
transmitted to the plugin for further processing.

In our example from :ref:`intro`, perhaps each of the different service types
is managed by a plugin, and so the main program would decode the block headers
to learn which plugins are needed, but process the block bodies dynamically:

.. code-block:: go

   type ServiceConfig struct {
     Type         string   `hcl:"type,label"`
     Name         string   `hcl:"name,label"`
     PluginConfig hcl.Body `hcl:",remain"`
   }
   type Config struct {
     IOMode   string          `hcl:"io_mode"`
     Services []ServiceConfig `hcl:"service,block"`
   }

   var c Config
   moreDiags := gohcl.DecodeBody(f.Body, nil, &c)
   diags = append(diags, moreDiags...)
   if moreDiags.HasErrors() {
       // (show diags in the UI)
       return
   }

   for _, sc := range c.Services {
       pluginName := block.Type

       // Totally-hypothetical plugin manager (not part of HCL)
       plugin, err := pluginMgr.GetPlugin(pluginName)
       if err != nil {
           diags = diags.Append(&hcl.Diagnostic{ /* ... */ })
           continue
       }
       spec := plugin.ConfigSpec() // returns hcldec.Spec

       // Decode the block body using the plugin's given specification
       configVal, moreDiags := hcldec.Decode(sc.PluginConfig, spec, nil)
       diags = append(diags, moreDiags...)
       if moreDiags.HasErrors() {
           continue
       }

       // Again, hypothetical API within your application itself, and not
       // part of HCL. Perhaps plugin system serializes configVal as JSON
       // and sends it over to the plugin.
       svc := plugin.NewService(configVal)
       serviceMgr.AddService(sc.Name, svc)
   }


Variables and Functions
-----------------------

The final argument to ``hcldec.Decode`` is an expression evaluation context,
just as with ``gohcl.DecodeBlock``.

This object can be constructed using
:ref:`the gohcl helper function <go-decoding-gohcl-evalcontext>` as before if desired, but
you can also choose to work directly with :go:type:`hcl.EvalContext` as
discussed in :ref:`go-expression-eval`:

.. code-block:: go

   ctx := &hcl.EvalContext{
       Variables: map[string]cty.Value{
           "pid": cty.NumberIntVal(int64(os.Getpid())),
       },
   }
  val, moreDiags := hcldec.Decode(f.Body, spec, ctx)
  diags = append(diags, moreDiags...)

As you can see, this lower-level API also uses :go:pkg:`cty`, so it can be
particularly convenient in situations where the result of dynamically decoding
one block must be available to expressions in another block.

.. _intro:

Introduction to HCL
===================

HCL-based configuration is built from two main constructs: arguments and
blocks. The following is an example of a configuration language for a
hypothetical application:

.. code-block:: hcl

  io_mode = "async"

  service "http" "web_proxy" {
    listen_addr = "127.0.0.1:8080"

    process "main" {
      command = ["/usr/local/bin/awesome-app", "server"]
    }

    process "mgmt" {
      command = ["/usr/local/bin/awesome-app", "mgmt"]
    }
  }

In the above example, ``io_mode`` is a top-level argument, while ``service``
introduces a block. Within the body of a block, further arguments and nested
blocks are allowed. A block type may also expect a number of *labels*, which
are the quoted names following the ``service`` keyword in the above example.

The specific keywords ``io_mode``, ``service``, ``process``, etc here are
application-defined. HCL provides the general block structure syntax, and
can validate and decode configuration based on the application's provided
schema.

HCL is a structured configuration language rather than a data structure
serialization language. This means that unlike languages such as JSON, YAML,
or TOML, HCL is always decoded using an application-defined schema.

However, HCL does have a JSON-based alternative syntax, which allows the same
structure above to be generated using a standard JSON serializer when users
wish to generate configuration programmatically rather than hand-write it:

.. code-block:: json

  {
    "io_mode": "async",
    "service": {
      "http": {
        "web_proxy": {
          "listen_addr": "127.0.0.1:8080",
          "process": {
            "main": {
              "command": ["/usr/local/bin/awesome-app", "server"]
            },
            "mgmt": {
              "command": ["/usr/local/bin/awesome-app", "mgmt"]
            },
          }
        }
      }
    }
  }

The calling application can choose which syntaxes to support. JSON syntax may
not be important or desirable for certain applications, but it is available for
applications that need it. The schema provided by the calling application
allows JSON input to be properly decoded even though JSON syntax is ambiguous
in various ways, such as whether a JSON object is representing a nested block
or an object expression.

The collection of arguments and blocks at a particular nesting level is called
a *body*. A file always has a root body containing the top-level elements,
and each block also has its own body representing the elements within it.

The term "attribute" can also be used to refer to what we've called an
"argument" so far. The term "attribute" is also used for the fields of an
object value in argument expressions, and so "argument" is used to refer
specifically to the type of attribute that appears directly within a body.

The above examples show the general "texture" of HCL-based configuration. The
full details of the syntax are covered in the language specifications.

.. todo:: Once the language specification documents have settled into a
   final location, link them from above.

Argument Expressions
--------------------

The value of an argument can be a literal value shown above, or it may be an
expression to allow arithmetic, deriving one value from another, etc.

.. code-block:: hcl

  listen_addr = env.LISTEN_ADDR

Built-in arithmetic and comparison operators are automatically available in all
HCL-based configuration languages. A calling application may optionally
provide variables that users can reference, like ``env`` in the above example,
and custom functions to transform values in application-specific ways.

Full details of the expression syntax are in the HCL native syntax
specification. Since JSON does not have an expression syntax, JSON-based
configuration files use the native syntax expression language embedded inside
JSON strings.

.. todo:: Once the language specification documents have settled into a
   final location, link to the native syntax specification from above.

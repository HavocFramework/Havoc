Configuration Language Design
=============================

In this section we will cover some conventions for HCL-based configuration
languages that can help make them feel consistent with other HCL-based
languages, and make the best use of HCL's building blocks.

HCL's native and JSON syntaxes both define a mapping from input bytes to a
higher-level information model. In designing a configuration language based on
HCL, your building blocks are the components in that information model:
blocks, arguments, and expressions.

Each calling application of HCL, then, effectively defines its own language.
Just as Atom and RSS are higher-level languages built on XML, HashiCorp
Terraform has a higher-level language built on HCL, while HashiCorp Nomad has
its own distinct language that is *also* built on HCL.

From an end-user perspective, these are distinct languages but have a common
underlying texture. Users of both are therefore likely to bring some
expectations from one to the other, and so this section is an attempt to
codify some of these shared expectations to reduce user surprise.

These are subjective guidelines however, and so applications may choose to
ignore them entirely or ignore them in certain specialized cases. An
application providing a configuration language for a pre-existing system, for
example, may choose to eschew the identifier naming conventions in this section
in order to exactly match the existing names in that underlying system.

Language Keywords and Identifiers
---------------------------------

Much of the work in defining an HCL-based language is in selecting good names
for arguments, block types, variables, and functions.

The standard for naming in HCL is to use all-lowercase identifiers with
underscores separating words, like ``service`` or ``io_mode``. HCL identifiers
do allow uppercase letters and dashes, but this primarily for natural
interfacing with external systems that may have other identifier conventions,
and so these should generally be avoided for the identifiers native to your
own language.

The distinction between "keywords" and other identifiers is really just a
convention. In your own language documentation, you may use the word "keyword"
to refer to names that are presented as an intrinsic part of your language,
such as important top-level block type names.

Block type names are usually singular, since each block defines a single
object. Use a plural block name only if the block is serving only as a
namespacing container for a number of other objects. A block with a plural
type name will generally contain only nested blocks, and no arguments of its
own.

Argument names are also singular unless they expect a collection value, in
which case they should be plural. For example, ``name = "foo"`` but
``subnet_ids = ["abc", "123"]``.

Function names will generally *not* use underscores and will instead just run
words together, as is common in the C standard library. This is a result of
the fact that several of the standard library functions offered in ``cty``
(covered in a later section) have names that follow C library function names
like ``substr``. This is not a strong rule, and applications that use longer
names may choose to use underscores for them to improve readability.

Blocks vs. Object Values
------------------------

HCL blocks and argument values of object type have quite a similar appearance
in the native syntax, and are identical in JSON syntax:

.. code-block:: hcl

   block {
     foo = bar
   }

   # argument with object constructor expression
   argument = {
     foo = bar
   }

In spite of this superficial similarity, there are some important differences
between these two forms.

The most significant difference is that a child block can contain nested blocks
of its own, while an object constructor expression can define only attributes
of the object it is creating.

The user-facing model for blocks is that they generally form the more "rigid"
structure of the language itself, while argument values can be more free-form.
An application will generally define in its schema and documentation all of
the arguments that are valid for a particular block type, while arguments
accepting object constructors are more appropriate for situations where the
arguments themselves are freely selected by the user, such as when the
expression will be converted by the application to a map type.

As a less contrived example, consider the ``resource`` block type in Terraform
and its use with a particular resource type ``aws_instance``:

.. code-block:: hcl

   resource "aws_instance" "example" {
     ami           = "ami-abc123"
     instance_type = "t2.micro"

     tags = {
       Name = "example instance"
     }

     ebs_block_device {
       device_name = "hda1"
       volume_size = 8
       volume_type = "standard"
     }
   }

The top-level block type ``resource`` is fundamental to Terraform itself and
so an obvious candidate for block syntax: it maps directly onto an object in
Terraform's own domain model.

Within this block we see a mixture of arguments and nested blocks, all defined
as part of the schema of the ``aws_instance`` resource type. The ``tags``
map here is specified as an argument because its keys are free-form, chosen
by the user and mapped directly onto a map in the underlying system.
``ebs_block_device`` is specified as a nested block, because it is a separate
domain object within the remote system and has a rigid schema of its own.

As a special case, block syntax may sometimes be used with free-form keys if
those keys each serve as a separate declaration of some first-class object
in the language. For example, Terraform has a top-level block type ``locals``
which behaves in this way:

.. code-block:: hcl

   locals {
     instance_type = "t2.micro"
     instance_id   = aws_instance.example.id
   }

Although the argument names in this block are arbitrarily selected by the
user, each one defines a distinct top-level object. In other words, this
approach is used to create a more ergonomic syntax for defining these simple
single-expression objects, as a pragmatic alternative to more verbose and
redundant declarations using blocks:

.. code-block:: hcl

   local "instance_type" {
     value = "t2.micro"
   }
   local "instance_id" {
     value = aws_instance.example.id
   }

The distinction between domain objects, language constructs and user data will
always be subjective, so the final decision is up to you as the language
designer.

Standard Functions
------------------

HCL itself does not define a common set of functions available in all HCL-based
languages; the built-in language operators give a baseline of functionality
that is always available, but applications are free to define functions as they
see fit.

With that said, there's a number of generally-useful functions that don't
belong to the domain of any one application: string manipulation, sequence
manipulation, date formatting, JSON serialization and parsing, etc.

Given the general need such functions serve, it's helpful if a similar set of
functions is available with compatible behavior across multiple HCL-based
languages, assuming the language is for an application where function calls
make sense at all.

The Go implementation of HCL is built on an underlying type and function system
:go:pkg:`cty`, whose usage was introduced in :ref:`go-expression-funcs`. That
library also has a package of "standard library" functions which we encourage
applications to offer with consistent names and compatible behavior, either by
using the standard implementations directly or offering compatible
implementations under the same name.

The "standard" functions that new configuration formats should consider
offering are:

* ``abs(number)`` - returns the absolute (positive) value of the given number.
* ``coalesce(vals...)`` - returns the value of the first argument that isn't null. Useful only in formats where null values may appear.
* ``compact(vals...)`` - returns a new tuple with the non-null values given as arguments, preserving order.
* ``concat(seqs...)`` - builds a tuple value by concatenating together all of the given sequence (list or tuple) arguments.
* ``format(fmt, args...)`` - performs simple string formatting similar to the C library function ``printf``.
* ``hasindex(coll, idx)`` - returns true if the given collection has the given index. ``coll`` may be of list, tuple, map, or object type.
* ``int(number)`` - returns the integer component of the given number, rounding towards zero.
* ``jsondecode(str)`` - interprets the given string as JSON format and return the corresponding decoded value.
* ``jsonencode(val)`` - encodes the given value as a JSON string.
* ``length(coll)`` - returns the length of the given collection.
* ``lower(str)`` - converts the letters in the given string to lowercase, using Unicode case folding rules.
* ``max(numbers...)`` - returns the highest of the given number values.
* ``min(numbers...)`` - returns the lowest of the given number values.
* ``sethas(set, val)`` - returns true only if the given set has the given value as an element.
* ``setintersection(sets...)`` - returns the intersection of the given sets
* ``setsubtract(set1, set2)`` - returns a set with the elements from ``set1`` that are not also in ``set2``.
* ``setsymdiff(sets...)`` - returns the symmetric difference of the given sets.
* ``setunion(sets...)`` - returns the union of the given sets.
* ``strlen(str)`` - returns the length of the given string in Unicode grapheme clusters.
* ``substr(str, offset, length)`` - returns a substring from the given string by splitting it between Unicode grapheme clusters.
* ``timeadd(time, duration)`` - takes a timestamp in RFC3339 format and a possibly-negative duration given as a string like ``"1h"`` (for "one hour") and returns a new RFC3339 timestamp after adding the duration to the given timestamp.
* ``upper(str)`` - converts the letters in the given string to uppercase, using Unicode case folding rules.

Not all of these functions will make sense in all applications. For example, an
application that doesn't use set types at all would have no reason to provide
the set-manipulation functions here.

Some languages will not provide functions at all, since they are primarily for
assigning values to arguments and thus do not need nor want any custom
computations of those values.

Block Results as Expression Variables
-------------------------------------

In some applications, top-level blocks serve also as declarations of variables
(or of attributes of object variables) available during expression evaluation,
as discussed in :ref:`go-interdep-blocks`.

In this case, it's most intuitive for the variables map in the evaluation
context to contain an value named after each valid top-level block
type and for these values to be object-typed or map-typed and reflect the
structure implied by block type labels.

For example, an application may have a top-level ``service`` block type
used like this:

.. code-block:: hcl

  service "http" "web_proxy" {
    listen_addr = "127.0.0.1:8080"

    process "main" {
      command = ["/usr/local/bin/awesome-app", "server"]
    }

    process "mgmt" {
      command = ["/usr/local/bin/awesome-app", "mgmt"]
    }
  }

If the result of decoding this block were available for use in expressions
elsewhere in configuration, the above convention would call for it to be
available to expressions as an object at ``service.http.web_proxy``.

If it the contents of the block itself that are offered to evaluation -- or
a superset object *derived* from the block contents -- then the block arguments
can map directly to object attributes, but it is up to the application to
decide which value type is most appropriate for each block type, since this
depends on how multiple blocks of the same type relate to one another, or if
multiple blocks of that type are even allowed.

In the above example, an application would probably expose the ``listen_addr``
argument value as ``service.http.web_proxy.listen_addr``, and may choose to
expose the ``process`` blocks as a map of objects using the labels as keys,
which would allow an expression like
``service.http.web_proxy.service["main"].command``.

If multiple blocks of a given type do not have a significant order relative to
one another, as seems to be the case with these ``process`` blocks,
representation as a map is often the most intuitive. If the ordering of the
blocks *is* significant then a list may be more appropriate, allowing the use
of HCL's "splat operators" for convenient access to child arguments. However,
there is no one-size-fits-all solution here and language designers must
instead consider the likely usage patterns of each value and select the
value representation that best accommodates those patterns.

Some applications may choose to offer variables with slightly different names
than the top-level blocks in order to allow for more concise references, such
as abbreviating ``service`` to ``svc`` in the above examples. This should be
done with care since it may make the relationship between the two less obvious,
but this may be a good tradeoff for names that are accessed frequently that
might otherwise hurt the readability of expressions they are embedded in.
Familiarity permits brevity.

Many applications will not make blocks results available for use in other
expressions at all, in which case they are free to select whichever variable
names make sense for what is being exposed. For example, a format may make
environment variable values available for use in expressions, and may do so
either as top-level variables (if no other variables are needed) or as an
object named ``env``, which can be used as in ``env.HOME``.

Text Editor and IDE Integrations
--------------------------------

Since HCL defines only low-level syntax, a text editor or IDE integration for
HCL itself can only really provide basic syntax highlighting.

For non-trivial HCL-based languages, a more specialized editor integration may
be warranted. For example, users writing configuration for HashiCorp Terraform
must recall the argument names for numerous different provider plugins, and so
auto-completion and documentation hovertips can be a great help, and
configurations are commonly spread over multiple files making "Go to Definition"
functionality useful. None of this functionality can be implemented generically
for all HCL-based languages since it relies on knowledge of the structure of
Terraform's own language.

Writing such text editor integrations is out of the scope of this guide. The
Go implementation of HCL does have some building blocks to help with this, but
it will always be an application-specific effort.

However, in order to *enable* such integrations, it is best to establish a
conventional file extension *other than* `.hcl` for each non-trivial HCL-based
language, thus allowing text editors to recognize it and enable the suitable
integration. For example, Terraform requires ``.tf`` and ``.tf.json`` filenames
for its main configuration, and the ``hcldec`` utility in the HCL repository
accepts spec files that should conventionally be named with an ``.hcldec``
extension.

For simple languages that are unlikely to benefit from specific editor
integrations, using the ``.hcl`` extension is fine and may cause an editor to
enable basic syntax highlighting, absent any other deeper features. An editor
extension for a specific HCL-based language should *not* match generically the
``.hcl`` extension, since this can cause confusing results for users
attempting to write configuration files targeting other applications.

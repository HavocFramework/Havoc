package tryfunc

import (
    "testing"

    "Havoc/pkg/profile/yaotl"
    "Havoc/pkg/profile/yaotl/hclsyntax"
    "github.com/zclconf/go-cty/cty"
    "github.com/zclconf/go-cty/cty/function"
)

func TestTryFunc(t *testing.T) {
    tests := map[string]struct {
        expr    string
        vars    map[string]cty.Value
        want    cty.Value
        wantErr string
    }{
        "one argument succeeds": {
            `try(1)`,
            nil,
            cty.NumberIntVal(1),
            ``,
        },
        "one marked argument succeeds": {
            `try(sensitive)`,
            map[string]cty.Value{
                "sensitive": cty.StringVal("secret").Mark("porpoise"),
            },
            cty.StringVal("secret").Mark("porpoise"),
            ``,
        },
        "two arguments, first succeeds": {
            `try(1, 2)`,
            nil,
            cty.NumberIntVal(1),
            ``,
        },
        "two arguments, first fails": {
            `try(nope, 2)`,
            nil,
            cty.NumberIntVal(2),
            ``,
        },
        "two arguments, first depends on unknowns": {
            `try(unknown, 2)`,
            map[string]cty.Value{
                "unknown": cty.UnknownVal(cty.Number),
            },
            cty.DynamicVal, // can't proceed until first argument is known
            ``,
        },
        "two arguments, first succeeds and second depends on unknowns": {
            `try(1, unknown)`,
            map[string]cty.Value{
                "unknown": cty.UnknownVal(cty.Number),
            },
            cty.NumberIntVal(1), // we know 1st succeeds, so it doesn't matter that 2nd is unknown
            ``,
        },
        "two arguments, first depends on unknowns deeply": {
            `try(has_unknowns, 2)`,
            map[string]cty.Value{
                "has_unknowns": cty.ListVal([]cty.Value{cty.UnknownVal(cty.Bool)}),
            },
            cty.DynamicVal, // can't proceed until first argument is wholly known
            ``,
        },
        "two arguments, first traverses through an unkown": {
            `try(unknown.baz, 2)`,
            map[string]cty.Value{
                "unknown": cty.UnknownVal(cty.Map(cty.String)),
            },
            cty.DynamicVal, // can't proceed until first argument is wholly known
            ``,
        },
        "two arguments, both marked, first succeeds": {
            `try(sensitive, other)`,
            map[string]cty.Value{
                "sensitive": cty.StringVal("secret").Mark("porpoise"),
                "other":     cty.StringVal("that").Mark("a"),
            },
            cty.StringVal("secret").Mark("porpoise"),
            ``,
        },
        "two arguments, both marked, second succeeds": {
            `try(sensitive, other)`,
            map[string]cty.Value{
                "other": cty.StringVal("that").Mark("a"),
            },
            cty.StringVal("that").Mark("a"),
            ``,
        },
        "two arguments, result is element of marked list ": {
            `try(sensitive[0], other)`,
            map[string]cty.Value{
                "sensitive": cty.ListVal([]cty.Value{
                    cty.StringVal("list"),
                    cty.StringVal("of "),
                    cty.StringVal("secrets"),
                }).Mark("secret"),
                "other": cty.StringVal("not"),
            },
            cty.StringVal("list").Mark("secret"),
            ``,
        },
        "three arguments, all fail": {
            `try(this, that, this_thing_in_particular)`,
            nil,
            cty.NumberIntVal(2),
            // The grammar of this stringification of the message is unfortunate,
            // but caller can type-assert our result to get the original
            // diagnostics directly in order to produce a better result.
            `test.hcl:1,1-5: Error in function call; Call to function "try" failed: no expression succeeded:
- Variables not allowed (at test.hcl:1,5-9)
  Variables may not be used here.
- Variables not allowed (at test.hcl:1,11-15)
  Variables may not be used here.
- Variables not allowed (at test.hcl:1,17-41)
  Variables may not be used here.

At least one expression must produce a successful result.`,
        },
        "no arguments": {
            `try()`,
            nil,
            cty.NilVal,
            `test.hcl:1,1-5: Error in function call; Call to function "try" failed: at least one argument is required.`,
        },
    }

    for k, test := range tests {
        t.Run(k, func(t *testing.T) {
            expr, diags := hclsyntax.ParseExpression([]byte(test.expr), "test.hcl", hcl.Pos{Line: 1, Column: 1})
            if diags.HasErrors() {
                t.Fatalf("unexpected problems: %s", diags.Error())
            }

            ctx := &hcl.EvalContext{
                Variables: test.vars,
                Functions: map[string]function.Function{
                    "try": TryFunc,
                },
            }

            got, err := expr.Value(ctx)

            if err != nil {
                if test.wantErr != "" {
                    if got, want := err.Error(), test.wantErr; got != want {
                        t.Errorf("wrong error\ngot:  %s\nwant: %s", got, want)
                    }
                } else {
                    t.Errorf("unexpected error\ngot:  %s\nwant: <nil>", err)
                }
                return
            }
            if test.wantErr != "" {
                t.Errorf("wrong error\ngot:  <nil>\nwant: %s", test.wantErr)
            }

            if !test.want.RawEquals(got) {
                t.Errorf("wrong result\ngot:  %#v\nwant: %#v", got, test.want)
            }
        })
    }
}

func TestCanFunc(t *testing.T) {
    tests := map[string]struct {
        expr string
        vars map[string]cty.Value
        want cty.Value
    }{
        "succeeds": {
            `can(1)`,
            nil,
            cty.True,
        },
        "fails": {
            `can(nope)`,
            nil,
            cty.False,
        },
        "simple unknown": {
            `can(unknown)`,
            map[string]cty.Value{
                "unknown": cty.UnknownVal(cty.Number),
            },
            cty.UnknownVal(cty.Bool),
        },
        "traversal through unknown": {
            `can(unknown.foo)`,
            map[string]cty.Value{
                "unknown": cty.UnknownVal(cty.Map(cty.Number)),
            },
            cty.UnknownVal(cty.Bool),
        },
        "deep unknown": {
            `can(has_unknown)`,
            map[string]cty.Value{
                "has_unknown": cty.ListVal([]cty.Value{cty.UnknownVal(cty.Bool)}),
            },
            cty.UnknownVal(cty.Bool),
        },
    }

    for k, test := range tests {
        t.Run(k, func(t *testing.T) {
            expr, diags := hclsyntax.ParseExpression([]byte(test.expr), "test.hcl", hcl.Pos{Line: 1, Column: 1})
            if diags.HasErrors() {
                t.Fatalf("unexpected problems: %s", diags.Error())
            }

            ctx := &hcl.EvalContext{
                Variables: test.vars,
                Functions: map[string]function.Function{
                    "can": CanFunc,
                },
            }

            got, err := expr.Value(ctx)
            if err != nil {
                t.Errorf("unexpected error\ngot:  %s\nwant: <nil>", err)
            }
            if !test.want.RawEquals(got) {
                t.Errorf("wrong result\ngot:  %#v\nwant: %#v", got, test.want)
            }
        })
    }
}

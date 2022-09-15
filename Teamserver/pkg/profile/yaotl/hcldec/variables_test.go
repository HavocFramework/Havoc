package hcldec

import (
    "fmt"
    "reflect"
    "testing"

    "Havoc/pkg/profile/yaotl"
    "Havoc/pkg/profile/yaotl/hclsyntax"
    "github.com/zclconf/go-cty/cty"
)

func TestVariables(t *testing.T) {
    tests := []struct {
        config string
        spec   Spec
        want   []hcl.Traversal
    }{
        {
            ``,
            &ObjectSpec{},
            nil,
        },
        {
            "a = foo\n",
            &ObjectSpec{},
            nil, // "a" is not actually used, so "foo" is not required
        },
        {
            "a = foo\n",
            &AttrSpec{
                Name: "a",
            },
            []hcl.Traversal{
                {
                    hcl.TraverseRoot{
                        Name: "foo",
                        SrcRange: hcl.Range{
                            Start: hcl.Pos{Line: 1, Column: 5, Byte: 4},
                            End:   hcl.Pos{Line: 1, Column: 8, Byte: 7},
                        },
                    },
                },
            },
        },
        {
            "a = foo\nb = bar\n",
            &DefaultSpec{
                Primary: &AttrSpec{
                    Name: "a",
                },
                Default: &AttrSpec{
                    Name: "b",
                },
            },
            []hcl.Traversal{
                {
                    hcl.TraverseRoot{
                        Name: "foo",
                        SrcRange: hcl.Range{
                            Start: hcl.Pos{Line: 1, Column: 5, Byte: 4},
                            End:   hcl.Pos{Line: 1, Column: 8, Byte: 7},
                        },
                    },
                },
                {
                    hcl.TraverseRoot{
                        Name: "bar",
                        SrcRange: hcl.Range{
                            Start: hcl.Pos{Line: 2, Column: 5, Byte: 12},
                            End:   hcl.Pos{Line: 2, Column: 8, Byte: 15},
                        },
                    },
                },
            },
        },
        {
            "a = foo\n",
            &ObjectSpec{
                "a": &AttrSpec{
                    Name: "a",
                },
            },
            []hcl.Traversal{
                {
                    hcl.TraverseRoot{
                        Name: "foo",
                        SrcRange: hcl.Range{
                            Start: hcl.Pos{Line: 1, Column: 5, Byte: 4},
                            End:   hcl.Pos{Line: 1, Column: 8, Byte: 7},
                        },
                    },
                },
            },
        },
        {
            `
b {
  a = foo
}
`,
            &BlockSpec{
                TypeName: "b",
                Nested: &AttrSpec{
                    Name: "a",
                },
            },
            []hcl.Traversal{
                {
                    hcl.TraverseRoot{
                        Name: "foo",
                        SrcRange: hcl.Range{
                            Start: hcl.Pos{Line: 3, Column: 7, Byte: 11},
                            End:   hcl.Pos{Line: 3, Column: 10, Byte: 14},
                        },
                    },
                },
            },
        },
        {
            `
b {
  a = foo
  b = bar
}
`,
            &BlockAttrsSpec{
                TypeName:    "b",
                ElementType: cty.String,
            },
            []hcl.Traversal{
                {
                    hcl.TraverseRoot{
                        Name: "foo",
                        SrcRange: hcl.Range{
                            Start: hcl.Pos{Line: 3, Column: 7, Byte: 11},
                            End:   hcl.Pos{Line: 3, Column: 10, Byte: 14},
                        },
                    },
                },
                {
                    hcl.TraverseRoot{
                        Name: "bar",
                        SrcRange: hcl.Range{
                            Start: hcl.Pos{Line: 4, Column: 7, Byte: 21},
                            End:   hcl.Pos{Line: 4, Column: 10, Byte: 24},
                        },
                    },
                },
            },
        },
        {
            `
b {
  a = foo
}
b {
  a = bar
}
c {
  a = baz
}
`,
            &BlockListSpec{
                TypeName: "b",
                Nested: &AttrSpec{
                    Name: "a",
                },
            },
            []hcl.Traversal{
                {
                    hcl.TraverseRoot{
                        Name: "foo",
                        SrcRange: hcl.Range{
                            Start: hcl.Pos{Line: 3, Column: 7, Byte: 11},
                            End:   hcl.Pos{Line: 3, Column: 10, Byte: 14},
                        },
                    },
                },
                {
                    hcl.TraverseRoot{
                        Name: "bar",
                        SrcRange: hcl.Range{
                            Start: hcl.Pos{Line: 6, Column: 7, Byte: 27},
                            End:   hcl.Pos{Line: 6, Column: 10, Byte: 30},
                        },
                    },
                },
            },
        },
    }

    for i, test := range tests {
        t.Run(fmt.Sprintf("%02d-%s", i, test.config), func(t *testing.T) {
            file, diags := hclsyntax.ParseConfig([]byte(test.config), "", hcl.Pos{Line: 1, Column: 1, Byte: 0})
            if len(diags) != 0 {
                t.Errorf("wrong number of diagnostics from ParseConfig %d; want %d", len(diags), 0)
                for _, diag := range diags {
                    t.Logf(" - %s", diag.Error())
                }
            }
            body := file.Body

            got := Variables(body, test.spec)

            if !reflect.DeepEqual(got, test.want) {
                t.Errorf("wrong result\ngot:  %#v\nwant: %#v", got, test.want)
            }
        })
    }

}

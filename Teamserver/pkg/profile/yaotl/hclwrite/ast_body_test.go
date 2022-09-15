package hclwrite

import (
    "fmt"
    "reflect"
    "strings"
    "testing"

    "github.com/davecgh/go-spew/spew"
    "github.com/google/go-cmp/cmp"
    "Havoc/pkg/profile/yaotl"
    "Havoc/pkg/profile/yaotl/hclsyntax"
    "github.com/zclconf/go-cty/cty"
)

func TestBodyGetAttribute(t *testing.T) {
    tests := []struct {
        src  string
        name string
        want Tokens
    }{
        {
            "",
            "a",
            nil,
        },
        {
            "a = 1\n",
            "a",
            Tokens{
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte{'a'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEqual,
                    Bytes:        []byte{'='},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNumberLit,
                    Bytes:        []byte{'1'},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
            },
        },
        {
            "a = 1\nb = 1\nc = 1\n",
            "a",
            Tokens{
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte{'a'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEqual,
                    Bytes:        []byte{'='},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNumberLit,
                    Bytes:        []byte{'1'},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
            },
        },
        {
            "a = 1\nb = 2\nc = 3\n",
            "b",
            Tokens{
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte{'b'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEqual,
                    Bytes:        []byte{'='},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNumberLit,
                    Bytes:        []byte{'2'},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
            },
        },
        {
            "a = 1\nb = 2\nc = 3\n",
            "c",
            Tokens{
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte{'c'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEqual,
                    Bytes:        []byte{'='},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNumberLit,
                    Bytes:        []byte{'3'},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
            },
        },
        {
            "a = 1\n# b is a b\nb = 2\nc = 3\n",
            "b",
            Tokens{
                {
                    // Recognized as a lead comment and so attached to the attribute
                    Type:         hclsyntax.TokenComment,
                    Bytes:        []byte("# b is a b\n"),
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte{'b'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEqual,
                    Bytes:        []byte{'='},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNumberLit,
                    Bytes:        []byte{'2'},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
            },
        },
        {
            "a = 1\n# not attached to a or b\n\nb = 2\nc = 3\n",
            "b",
            Tokens{
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte{'b'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEqual,
                    Bytes:        []byte{'='},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNumberLit,
                    Bytes:        []byte{'2'},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
            },
        },
    }

    for _, test := range tests {
        t.Run(fmt.Sprintf("%s in %s", test.name, test.src), func(t *testing.T) {
            f, diags := ParseConfig([]byte(test.src), "", hcl.Pos{Line: 1, Column: 1})
            if len(diags) != 0 {
                for _, diag := range diags {
                    t.Logf("- %s", diag.Error())
                }
                t.Fatalf("unexpected diagnostics")
            }

            attr := f.Body().GetAttribute(test.name)
            if attr == nil {
                if test.want != nil {
                    t.Fatal("attribute not found, but want it to exist")
                }
            } else {
                if test.want == nil {
                    t.Fatal("attribute found, but expecting not found")
                }

                got := attr.BuildTokens(nil)
                if !reflect.DeepEqual(got, test.want) {
                    t.Errorf("wrong result\ngot:  %s\nwant: %s", spew.Sdump(got), spew.Sdump(test.want))
                }
            }
        })
    }
}

func TestBodyFirstMatchingBlock(t *testing.T) {
    src := `a = "b"
service {
  attr0 = "val0"
}
service "label1" {
  attr1 = "val1"
}
service "label1" "label2" {
  attr2 = "val2"
}
parent {
  attr3 = "val3"
  child {
    attr4 = "val4"
  }
}
`

    tests := []struct {
        src      string
        typeName string
        labels   []string
        want     string
    }{
        {
            src,
            "service",
            []string{},
            `service {
  attr0 = "val0"
}
`,
        },
        {
            src,
            "service",
            []string{"label1"},
            `service "label1" {
  attr1 = "val1"
}
`,
        },
        {
            src,
            "service",
            []string{"label1", "label2"},
            `service "label1" "label2" {
  attr2 = "val2"
}
`,
        },
        {
            src,
            "parent",
            []string{},
            `parent {
  attr3 = "val3"
  child {
    attr4 = "val4"
  }
}
`,
        },
        {
            src,
            "hoge",
            []string{},
            "",
        },
        {
            src,
            "hoge",
            []string{"label1"},
            "",
        },
        {
            src,
            "service",
            []string{"label2"},
            "",
        },
        {
            src,
            "service",
            []string{"label2", "label1"},
            "",
        },
        {
            src,
            "child",
            []string{},
            "",
        },
    }

    for _, test := range tests {
        t.Run(fmt.Sprintf("%s %s", test.typeName, strings.Join(test.labels, " ")), func(t *testing.T) {
            f, diags := ParseConfig([]byte(test.src), "", hcl.Pos{Line: 1, Column: 1})
            if len(diags) != 0 {
                for _, diag := range diags {
                    t.Logf("- %s", diag.Error())
                }
                t.Fatalf("unexpected diagnostics")
            }

            block := f.Body().FirstMatchingBlock(test.typeName, test.labels)
            if block == nil {
                if test.want != "" {
                    t.Fatal("block not found, but want it to exist")
                }
            } else {
                if test.want == "" {
                    t.Fatal("block found, but expecting not found")
                }

                got := string(block.BuildTokens(nil).Bytes())
                if got != test.want {
                    t.Errorf("wrong result\ngot:  %s\nwant: %s", got, test.want)
                }
            }
        })
    }
}

func TestBodySetAttributeValue(t *testing.T) {
    tests := []struct {
        src  string
        name string
        val  cty.Value
        want Tokens
    }{
        {
            "",
            "a",
            cty.True,
            Tokens{
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte{'a'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEqual,
                    Bytes:        []byte{'='},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte("true"),
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEOF,
                    Bytes:        []byte{},
                    SpacesBefore: 0,
                },
            },
        },
        {
            "b = false\n",
            "a",
            cty.True,
            Tokens{
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte{'b'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEqual,
                    Bytes:        []byte{'='},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte("false"),
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte{'a'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEqual,
                    Bytes:        []byte{'='},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte("true"),
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEOF,
                    Bytes:        []byte{},
                    SpacesBefore: 0,
                },
            },
        },
        {
            "a = false\n",
            "a",
            cty.True,
            Tokens{
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte{'a'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEqual,
                    Bytes:        []byte{'='},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte("true"),
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEOF,
                    Bytes:        []byte{},
                    SpacesBefore: 0,
                },
            },
        },
        {
            "a = 1\nb = false\n",
            "a",
            cty.True,
            Tokens{
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte{'a'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEqual,
                    Bytes:        []byte{'='},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte("true"),
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte{'b'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEqual,
                    Bytes:        []byte{'='},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte("false"),
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEOF,
                    Bytes:        []byte{},
                    SpacesBefore: 0,
                },
            },
        },
    }

    for _, test := range tests {
        t.Run(fmt.Sprintf("%s = %#v in %s", test.name, test.val, test.src), func(t *testing.T) {
            f, diags := ParseConfig([]byte(test.src), "", hcl.Pos{Line: 1, Column: 1})
            if len(diags) != 0 {
                for _, diag := range diags {
                    t.Logf("- %s", diag.Error())
                }
                t.Fatalf("unexpected diagnostics")
            }

            f.Body().SetAttributeValue(test.name, test.val)
            got := f.BuildTokens(nil)
            format(got)
            if !reflect.DeepEqual(got, test.want) {
                diff := cmp.Diff(test.want, got)
                t.Errorf("wrong result\ngot:  %s\nwant: %s\ndiff:\n%s", spew.Sdump(got), spew.Sdump(test.want), diff)
            }
        })
    }
}

func TestBodySetAttributeTraversal(t *testing.T) {
    tests := []struct {
        src  string
        name string
        trav string
        want Tokens
    }{
        {
            "",
            "a",
            `b`,
            Tokens{
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte{'a'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEqual,
                    Bytes:        []byte{'='},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte("b"),
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEOF,
                    Bytes:        []byte{},
                    SpacesBefore: 0,
                },
            },
        },
        {
            "",
            "a",
            `b.c.d`,
            Tokens{
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte{'a'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEqual,
                    Bytes:        []byte{'='},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte("b"),
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenDot,
                    Bytes:        []byte("."),
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte("c"),
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenDot,
                    Bytes:        []byte("."),
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte("d"),
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEOF,
                    Bytes:        []byte{},
                    SpacesBefore: 0,
                },
            },
        },
        {
            "",
            "a",
            `b[0]`,
            Tokens{
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte{'a'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEqual,
                    Bytes:        []byte{'='},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte("b"),
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenOBrack,
                    Bytes:        []byte("["),
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenNumberLit,
                    Bytes:        []byte("0"),
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenCBrack,
                    Bytes:        []byte("]"),
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEOF,
                    Bytes:        []byte{},
                    SpacesBefore: 0,
                },
            },
        },
        {
            "",
            "a",
            `b[0].c`,
            Tokens{
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte{'a'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEqual,
                    Bytes:        []byte{'='},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte("b"),
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenOBrack,
                    Bytes:        []byte("["),
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenNumberLit,
                    Bytes:        []byte("0"),
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenCBrack,
                    Bytes:        []byte("]"),
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenDot,
                    Bytes:        []byte("."),
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte("c"),
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEOF,
                    Bytes:        []byte{},
                    SpacesBefore: 0,
                },
            },
        },
    }

    for _, test := range tests {
        t.Run(fmt.Sprintf("%s = %s in %s", test.name, test.trav, test.src), func(t *testing.T) {
            f, diags := ParseConfig([]byte(test.src), "", hcl.Pos{Line: 1, Column: 1})
            if len(diags) != 0 {
                for _, diag := range diags {
                    t.Logf("- %s", diag.Error())
                }
                t.Fatalf("unexpected diagnostics")
            }

            traversal, diags := hclsyntax.ParseTraversalAbs([]byte(test.trav), "", hcl.Pos{Line: 1, Column: 1})
            if len(diags) != 0 {
                for _, diag := range diags {
                    t.Logf("- %s", diag.Error())
                }
                t.Fatalf("unexpected diagnostics from traversal")
            }

            f.Body().SetAttributeTraversal(test.name, traversal)
            got := f.BuildTokens(nil)
            format(got)
            if !reflect.DeepEqual(got, test.want) {
                diff := cmp.Diff(test.want, got)
                t.Errorf("wrong result\ngot:  %s\nwant: %s\ndiff:\n%s", spew.Sdump(got), spew.Sdump(test.want), diff)
            }
        })
    }
}

func TestBodySetAttributeRaw(t *testing.T) {
    tests := []struct {
        src    string
        name   string
        tokens Tokens
        want   Tokens
    }{
        {
            "",
            "a",
            Tokens{
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte(`true`),
                    SpacesBefore: 0,
                },
            },
            Tokens{
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte{'a'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEqual,
                    Bytes:        []byte{'='},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte("true"),
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEOF,
                    Bytes:        []byte{},
                    SpacesBefore: 0,
                },
            },
        },
        {
            "a = 23\n",
            "a",
            Tokens{
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte(`true`),
                    SpacesBefore: 0,
                },
            },
            Tokens{
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte{'a'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEqual,
                    Bytes:        []byte{'='},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte("true"),
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEOF,
                    Bytes:        []byte{},
                    SpacesBefore: 0,
                },
            },
        },
        {
            "b = 23\n",
            "a",
            Tokens{
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte(`true`),
                    SpacesBefore: 0,
                },
            },
            Tokens{
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte{'b'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEqual,
                    Bytes:        []byte{'='},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNumberLit,
                    Bytes:        []byte("23"),
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte{'a'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEqual,
                    Bytes:        []byte{'='},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte("true"),
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEOF,
                    Bytes:        []byte{},
                    SpacesBefore: 0,
                },
            },
        },
    }

    for _, test := range tests {
        t.Run(fmt.Sprintf("%s = %s in %s", test.name, test.tokens.Bytes(), test.src), func(t *testing.T) {
            f, diags := ParseConfig([]byte(test.src), "", hcl.Pos{Line: 1, Column: 1})
            if len(diags) != 0 {
                for _, diag := range diags {
                    t.Logf("- %s", diag.Error())
                }
                t.Fatalf("unexpected diagnostics")
            }

            f.Body().SetAttributeRaw(test.name, test.tokens)
            got := f.BuildTokens(nil)
            format(got)
            if !reflect.DeepEqual(got, test.want) {
                diff := cmp.Diff(test.want, got)
                t.Errorf("wrong result\ngot:  %s\nwant: %s\ndiff:\n%s", spew.Sdump(got), spew.Sdump(test.want), diff)
            }
        })
    }
}

func TestBodySetAttributeValueInBlock(t *testing.T) {
    src := `service "label1" {
  attr1 = "val1"
}
`
    tests := []struct {
        src      string
        typeName string
        labels   []string
        attr     string
        val      cty.Value
        want     string
    }{
        {
            src,
            "service",
            []string{"label1"},
            "attr1",
            cty.StringVal("updated1"),
            `service "label1" {
  attr1 = "updated1"
}
`,
        },
    }

    for _, test := range tests {
        t.Run(fmt.Sprintf("%s = %#v in %s %s", test.attr, test.val, test.typeName, strings.Join(test.labels, " ")), func(t *testing.T) {
            f, diags := ParseConfig([]byte(test.src), "", hcl.Pos{Line: 1, Column: 1})
            if len(diags) != 0 {
                for _, diag := range diags {
                    t.Logf("- %s", diag.Error())
                }
                t.Fatalf("unexpected diagnostics")
            }

            b := f.Body().FirstMatchingBlock(test.typeName, test.labels)
            b.Body().SetAttributeValue(test.attr, test.val)
            tokens := f.BuildTokens(nil)
            format(tokens)
            got := string(tokens.Bytes())
            if got != test.want {
                t.Errorf("wrong result\ngot:  %s\nwant: %s\n", got, test.want)
            }
        })
    }
}

func TestBodySetAttributeValueInNestedBlock(t *testing.T) {
    src := `parent {
  attr1 = "val1"
  child {
    attr2 = "val2"
  }
}
`
    tests := []struct {
        src            string
        parentTypeName string
        childTypeName  string
        attr           string
        val            cty.Value
        want           string
    }{
        {
            src,
            "parent",
            "child",
            "attr2",
            cty.StringVal("updated2"),
            `parent {
  attr1 = "val1"
  child {
    attr2 = "updated2"
  }
}
`,
        },
    }

    for _, test := range tests {
        t.Run(fmt.Sprintf("%s = %#v in %s in %s", test.attr, test.val, test.childTypeName, test.parentTypeName), func(t *testing.T) {
            f, diags := ParseConfig([]byte(test.src), "", hcl.Pos{Line: 1, Column: 1})
            if len(diags) != 0 {
                for _, diag := range diags {
                    t.Logf("- %s", diag.Error())
                }
                t.Fatalf("unexpected diagnostics")
            }

            parent := f.Body().FirstMatchingBlock(test.parentTypeName, []string{})
            child := parent.Body().FirstMatchingBlock(test.childTypeName, []string{})
            child.Body().SetAttributeValue(test.attr, test.val)
            tokens := f.BuildTokens(nil)
            format(tokens)
            got := string(tokens.Bytes())
            if got != test.want {
                t.Errorf("wrong result\ngot:  %s\nwant: %s\n", got, test.want)
            }
        })
    }
}

func TestBodyRemoveAttribute(t *testing.T) {
    tests := []struct {
        src  string
        name string
        want Tokens
    }{
        {
            "",
            "a",
            Tokens{
                {
                    Type:         hclsyntax.TokenEOF,
                    Bytes:        []byte{},
                    SpacesBefore: 0,
                },
            },
        },
        {
            "b = false\n",
            "a",
            Tokens{
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte{'b'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEqual,
                    Bytes:        []byte{'='},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte("false"),
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEOF,
                    Bytes:        []byte{},
                    SpacesBefore: 0,
                },
            },
        },
        {
            "a = false\n",
            "a",
            Tokens{
                {
                    Type:         hclsyntax.TokenEOF,
                    Bytes:        []byte{},
                    SpacesBefore: 0,
                },
            },
        },
        {
            "a = 1\nb = false\n",
            "a",
            Tokens{
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte{'b'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEqual,
                    Bytes:        []byte{'='},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte("false"),
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEOF,
                    Bytes:        []byte{},
                    SpacesBefore: 0,
                },
            },
        },
    }

    for _, test := range tests {
        t.Run(fmt.Sprintf("%s in %s", test.name, test.src), func(t *testing.T) {
            f, diags := ParseConfig([]byte(test.src), "", hcl.Pos{Line: 1, Column: 1})
            if len(diags) != 0 {
                for _, diag := range diags {
                    t.Logf("- %s", diag.Error())
                }
                t.Fatalf("unexpected diagnostics")
            }

            f.Body().RemoveAttribute(test.name)
            got := f.BuildTokens(nil)
            format(got)
            if !reflect.DeepEqual(got, test.want) {
                diff := cmp.Diff(test.want, got)
                t.Errorf("wrong result\ngot:  %s\nwant: %s\ndiff:\n%s", spew.Sdump(got), spew.Sdump(test.want), diff)
            }
        })
    }
}

func TestBodyAppendBlock(t *testing.T) {
    tests := []struct {
        src       string
        blockType string
        labels    []string
        want      Tokens
    }{
        {
            "",
            "foo",
            nil,
            Tokens{
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte(`foo`),
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenOBrace,
                    Bytes:        []byte{'{'},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenCBrace,
                    Bytes:        []byte{'}'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEOF,
                    Bytes:        []byte{},
                    SpacesBefore: 0,
                },
            },
        },
        {
            "",
            "foo",
            []string{"bar"},
            Tokens{
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte(`foo`),
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenOQuote,
                    Bytes:        []byte(`"`),
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenQuotedLit,
                    Bytes:        []byte(`bar`),
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenCQuote,
                    Bytes:        []byte(`"`),
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenOBrace,
                    Bytes:        []byte{'{'},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenCBrace,
                    Bytes:        []byte{'}'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEOF,
                    Bytes:        []byte{},
                    SpacesBefore: 0,
                },
            },
        },
        {
            "",
            "foo",
            []string{"bar", "baz"},
            Tokens{
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte(`foo`),
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenOQuote,
                    Bytes:        []byte(`"`),
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenQuotedLit,
                    Bytes:        []byte(`bar`),
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenCQuote,
                    Bytes:        []byte(`"`),
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenOQuote,
                    Bytes:        []byte(`"`),
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenQuotedLit,
                    Bytes:        []byte(`baz`),
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenCQuote,
                    Bytes:        []byte(`"`),
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenOBrace,
                    Bytes:        []byte{'{'},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenCBrace,
                    Bytes:        []byte{'}'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEOF,
                    Bytes:        []byte{},
                    SpacesBefore: 0,
                },
            },
        },
        {
            "bar {}\n",
            "foo",
            nil,
            Tokens{
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte(`bar`),
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenOBrace,
                    Bytes:        []byte{'{'},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenCBrace,
                    Bytes:        []byte{'}'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte(`foo`),
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenOBrace,
                    Bytes:        []byte{'{'},
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenCBrace,
                    Bytes:        []byte{'}'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte{'\n'},
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenEOF,
                    Bytes:        []byte{},
                    SpacesBefore: 0,
                },
            },
        },
    }

    for _, test := range tests {
        t.Run(fmt.Sprintf("%s %#v in %s", test.blockType, test.blockType, test.src), func(t *testing.T) {
            f, diags := ParseConfig([]byte(test.src), "", hcl.Pos{Line: 1, Column: 1})
            if len(diags) != 0 {
                for _, diag := range diags {
                    t.Logf("- %s", diag.Error())
                }
                t.Fatalf("unexpected diagnostics")
            }

            f.Body().AppendNewBlock(test.blockType, test.labels)
            got := f.BuildTokens(nil)
            format(got)
            if !reflect.DeepEqual(got, test.want) {
                diff := cmp.Diff(test.want, got)
                t.Errorf("wrong result\ngot:  %s\nwant: %s\ndiff:\n%s", spew.Sdump(got), spew.Sdump(test.want), diff)
            }
        })
    }
}

func TestBodyRemoveBlock(t *testing.T) {
    src := strings.TrimSpace(`
a = 1

# Foo
foo {
  b = 1
}
foo {
  b = 2
}
bar {}
`)
    f, diags := ParseConfig([]byte(src), "", hcl.Pos{Line: 1, Column: 1})
    if len(diags) != 0 {
        for _, diag := range diags {
            t.Logf("- %s", diag.Error())
        }
        t.Fatalf("unexpected diagnostics")
    }

    t.Logf("Removing the first block")
    t.Logf("initial content:\n%s", f.Bytes())
    body := f.Body()
    block := body.FirstMatchingBlock("foo", nil)
    if block == nil {
        t.Fatalf("didn't find a 'foo' block")
    }
    removed := body.RemoveBlock(block)
    if !removed {
        t.Fatalf("didn't remove first block")
    }
    t.Logf("updated content:\n%s", f.Bytes())
    got := f.BuildTokens(nil)
    want := Tokens{
        0: {
            Type:         hclsyntax.TokenIdent,
            Bytes:        []byte(`a`),
            SpacesBefore: 0,
        },
        1: {
            Type:         hclsyntax.TokenEqual,
            Bytes:        []byte(`=`),
            SpacesBefore: 1,
        },
        2: {
            Type:         hclsyntax.TokenNumberLit,
            Bytes:        []byte(`1`),
            SpacesBefore: 1,
        },
        3: {
            Type:         hclsyntax.TokenNewline,
            Bytes:        []byte("\n"),
            SpacesBefore: 0,
        },
        4: {
            Type:         hclsyntax.TokenNewline,
            Bytes:        []byte("\n"),
            SpacesBefore: 0,
        },
        5: {
            Type:         hclsyntax.TokenIdent,
            Bytes:        []byte(`foo`),
            SpacesBefore: 0,
        },
        6: {
            Type:         hclsyntax.TokenOBrace,
            Bytes:        []byte(`{`),
            SpacesBefore: 1,
        },
        7: {
            Type:         hclsyntax.TokenNewline,
            Bytes:        []byte("\n"),
            SpacesBefore: 0,
        },
        8: {
            Type:         hclsyntax.TokenIdent,
            Bytes:        []byte(`b`),
            SpacesBefore: 2,
        },
        9: {
            Type:         hclsyntax.TokenEqual,
            Bytes:        []byte(`=`),
            SpacesBefore: 1,
        },
        10: {
            Type:         hclsyntax.TokenNumberLit,
            Bytes:        []byte(`2`),
            SpacesBefore: 1,
        },
        11: {
            Type:         hclsyntax.TokenNewline,
            Bytes:        []byte("\n"),
            SpacesBefore: 0,
        },
        12: {
            Type:         hclsyntax.TokenCBrace,
            Bytes:        []byte(`}`),
            SpacesBefore: 0,
        },
        13: {
            Type:         hclsyntax.TokenNewline,
            Bytes:        []byte("\n"),
            SpacesBefore: 0,
        },
        14: {
            Type:         hclsyntax.TokenIdent,
            Bytes:        []byte(`bar`),
            SpacesBefore: 0,
        },
        15: {
            Type:         hclsyntax.TokenOBrace,
            Bytes:        []byte(`{`),
            SpacesBefore: 1,
        },
        16: {
            Type:         hclsyntax.TokenCBrace,
            Bytes:        []byte(`}`),
            SpacesBefore: 0,
        },
        17: {
            Type:         hclsyntax.TokenEOF,
            Bytes:        []byte(""),
            SpacesBefore: 0,
        },
    }
    format(got)
    if !reflect.DeepEqual(got, want) {
        diff := cmp.Diff(want, got)
        t.Errorf("wrong result\ngot:  %s\nwant: %s\ndiff:\n%s", spew.Sdump(got), spew.Sdump(want), diff)
    }

    t.Logf("removing the second block")
    t.Logf("initial content:\n%s", f.Bytes())
    block = body.FirstMatchingBlock("foo", nil)
    if block == nil {
        t.Fatalf("didn't find a 'foo' block")
    }
    removed = body.RemoveBlock(block)
    if !removed {
        t.Fatalf("didn't remove second block")
    }
    t.Logf("updated content:\n%s", f.Bytes())
    got = f.BuildTokens(nil)
    want = Tokens{
        0: {
            Type:         hclsyntax.TokenIdent,
            Bytes:        []byte(`a`),
            SpacesBefore: 0,
        },
        1: {
            Type:         hclsyntax.TokenEqual,
            Bytes:        []byte(`=`),
            SpacesBefore: 1,
        },
        2: {
            Type:         hclsyntax.TokenNumberLit,
            Bytes:        []byte(`1`),
            SpacesBefore: 1,
        },
        3: {
            Type:         hclsyntax.TokenNewline,
            Bytes:        []byte("\n"),
            SpacesBefore: 0,
        },
        4: {
            Type:         hclsyntax.TokenNewline,
            Bytes:        []byte("\n"),
            SpacesBefore: 0,
        },
        5: {
            Type:         hclsyntax.TokenIdent,
            Bytes:        []byte(`bar`),
            SpacesBefore: 0,
        },
        6: {
            Type:         hclsyntax.TokenOBrace,
            Bytes:        []byte(`{`),
            SpacesBefore: 1,
        },
        7: {
            Type:         hclsyntax.TokenCBrace,
            Bytes:        []byte(`}`),
            SpacesBefore: 0,
        },
        8: {
            Type:         hclsyntax.TokenEOF,
            Bytes:        []byte(""),
            SpacesBefore: 0,
        },
    }
    format(got)
    if !reflect.DeepEqual(got, want) {
        diff := cmp.Diff(want, got)
        t.Errorf("wrong result\ngot:  %s\nwant: %s\ndiff:\n%s", spew.Sdump(got), spew.Sdump(want), diff)
    }

}

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
)

func TestBlockType(t *testing.T) {
    tests := []struct {
        src  string
        want string
    }{
        {
            `
service {
  attr0 = "val0"
}
`,
            "service",
        },
    }

    for _, test := range tests {
        t.Run(fmt.Sprintf("%s", test.want), func(t *testing.T) {
            f, diags := ParseConfig([]byte(test.src), "", hcl.Pos{Line: 1, Column: 1})
            if len(diags) != 0 {
                for _, diag := range diags {
                    t.Logf("- %s", diag.Error())
                }
                t.Fatalf("unexpected diagnostics")
            }

            block := f.Body().Blocks()[0]
            got := string(block.Type())
            if got != test.want {
                t.Errorf("wrong result\ngot:  %s\nwant: %s", got, test.want)
            }
        })
    }
}

func TestBlockLabels(t *testing.T) {
    tests := []struct {
        src  string
        want []string
    }{
        {
            `
nolabel {
}
`,
            []string{},
        },
        {
            `
quoted "label1" {
}
`,
            []string{"label1"},
        },
        {
            `
quoted "label1" "label2" {
}
`,
            []string{"label1", "label2"},
        },
        {
            `
quoted "label1" /* foo */ "label2" {
}
`,
            []string{"label1", "label2"},
        },
        {
            `
unquoted label1 {
}
`,
            []string{"label1"},
        },
        {
            `
unquoted label1 /* foo */ label2 {
}
`,
            []string{"label1", "label2"},
        },
        {
            `
mixed label1 "label2" {
}
`,
            []string{"label1", "label2"},
        },
        {
            `
escape "\u0041" {
}
`,
            []string{"\u0041"},
        },
        {
            `
blank "" {
}
`,
            []string{""},
        },
    }

    for _, test := range tests {
        t.Run(fmt.Sprintf("%s", strings.Join(test.want, " ")), func(t *testing.T) {
            f, diags := ParseConfig([]byte(test.src), "", hcl.Pos{Line: 1, Column: 1})
            if len(diags) != 0 {
                for _, diag := range diags {
                    t.Logf("- %s", diag.Error())
                }
                t.Fatalf("unexpected diagnostics")
            }

            block := f.Body().Blocks()[0]
            got := block.Labels()
            if !reflect.DeepEqual(got, test.want) {
                t.Errorf("wrong result\ngot:  %#v\nwant: %#v", got, test.want)
            }
        })
    }
}

func TestBlockSetType(t *testing.T) {
    tests := []struct {
        src         string
        oldTypeName string
        newTypeName string
        labels      []string
        want        Tokens
    }{
        {
            "foo {}",
            "foo",
            "bar",
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
                    Type:         hclsyntax.TokenEOF,
                    Bytes:        []byte{},
                    SpacesBefore: 0,
                },
            },
        },
    }

    for _, test := range tests {
        t.Run(fmt.Sprintf("%s %s %s in %s", test.oldTypeName, test.newTypeName, test.labels, test.src), func(t *testing.T) {
            f, diags := ParseConfig([]byte(test.src), "", hcl.Pos{Line: 1, Column: 1})
            if len(diags) != 0 {
                for _, diag := range diags {
                    t.Logf("- %s", diag.Error())
                }
                t.Fatalf("unexpected diagnostics")
            }

            b := f.Body().FirstMatchingBlock(test.oldTypeName, test.labels)
            b.SetType(test.newTypeName)
            got := f.BuildTokens(nil)
            format(got)
            if !reflect.DeepEqual(got, test.want) {
                diff := cmp.Diff(test.want, got)
                t.Errorf("wrong result\ngot:  %s\nwant: %s\ndiff:\n%s", spew.Sdump(got), spew.Sdump(test.want), diff)
            }
        })
    }
}

func TestBlockSetLabels(t *testing.T) {
    tests := []struct {
        src       string
        typeName  string
        oldLabels []string
        newLabels []string
        want      Tokens
    }{
        {
            `foo "hoge" {}`,
            "foo",
            []string{"hoge"},
            []string{"fuga"}, // update first label
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
                    Bytes:        []byte(`fuga`),
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
                    Type:         hclsyntax.TokenCBrace,
                    Bytes:        []byte{'}'},
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
            `foo "hoge" "fuga" {}`,
            "foo",
            []string{"hoge", "fuga"},
            []string{"hoge", "piyo"}, // update second label
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
                    Bytes:        []byte(`hoge`),
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
                    Bytes:        []byte(`piyo`),
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
                    Type:         hclsyntax.TokenCBrace,
                    Bytes:        []byte{'}'},
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
            `foo {}`,
            "foo",
            []string{},
            []string{"fuga"}, // insert a new label to empty list
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
                    Bytes:        []byte(`fuga`),
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
                    Type:         hclsyntax.TokenCBrace,
                    Bytes:        []byte{'}'},
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
            `foo "hoge" {}`,
            "foo",
            []string{"hoge"},
            []string{}, // remove all labels
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
                    Type:         hclsyntax.TokenCBrace,
                    Bytes:        []byte{'}'},
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
            `foo "hoge" /* fuga */ "piyo" {}`,
            "foo",
            []string{"hoge", "piyo"},
            []string{"fuga"}, // force quoted form even if the old one is unquoted.
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
                    Bytes:        []byte(`fuga`),
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
                    Type:         hclsyntax.TokenCBrace,
                    Bytes:        []byte{'}'},
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
            `foo "hoge" /* foo */  "" {}`,
            "foo",
            []string{"hoge", ""},
            []string{"fuga"}, // force quoted form even if the old one is unquoted.
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
                    Bytes:        []byte(`fuga`),
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
                    Type:         hclsyntax.TokenCBrace,
                    Bytes:        []byte{'}'},
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
        t.Run(fmt.Sprintf("%s %s %s in %s", test.typeName, test.oldLabels, test.newLabels, test.src), func(t *testing.T) {
            f, diags := ParseConfig([]byte(test.src), "", hcl.Pos{Line: 1, Column: 1})
            if len(diags) != 0 {
                for _, diag := range diags {
                    t.Logf("- %s", diag.Error())
                }
                t.Fatalf("unexpected diagnostics")
            }

            b := f.Body().FirstMatchingBlock(test.typeName, test.oldLabels)
            b.SetLabels(test.newLabels)
            got := f.BuildTokens(nil)
            format(got)
            if !reflect.DeepEqual(got, test.want) {
                diff := cmp.Diff(test.want, got)
                t.Errorf("wrong result\ngot:  %s\nwant: %s\ndiff:\n%s", spew.Sdump(got), spew.Sdump(test.want), diff)
            }
        })
    }
}

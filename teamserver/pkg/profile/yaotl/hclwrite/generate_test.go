package hclwrite

import (
    "bytes"
    "math/big"
    "testing"

    "github.com/google/go-cmp/cmp"
    "Havoc/pkg/profile/yaotl"
    "Havoc/pkg/profile/yaotl/hclsyntax"
    "github.com/zclconf/go-cty/cty"
)

func TestTokensForValue(t *testing.T) {
    tests := []struct {
        Val  cty.Value
        Want Tokens
    }{
        {
            cty.NullVal(cty.DynamicPseudoType),
            Tokens{
                {
                    Type:  hclsyntax.TokenIdent,
                    Bytes: []byte(`null`),
                },
            },
        },
        {
            cty.True,
            Tokens{
                {
                    Type:  hclsyntax.TokenIdent,
                    Bytes: []byte(`true`),
                },
            },
        },
        {
            cty.False,
            Tokens{
                {
                    Type:  hclsyntax.TokenIdent,
                    Bytes: []byte(`false`),
                },
            },
        },
        {
            cty.NumberIntVal(0),
            Tokens{
                {
                    Type:  hclsyntax.TokenNumberLit,
                    Bytes: []byte(`0`),
                },
            },
        },
        {
            cty.NumberFloatVal(0.5),
            Tokens{
                {
                    Type:  hclsyntax.TokenNumberLit,
                    Bytes: []byte(`0.5`),
                },
            },
        },
        {
            cty.NumberVal(big.NewFloat(0).SetPrec(512).Mul(big.NewFloat(40000000), big.NewFloat(2000000))),
            Tokens{
                {
                    Type:  hclsyntax.TokenNumberLit,
                    Bytes: []byte(`80000000000000`),
                },
            },
        },
        {
            cty.StringVal(""),
            Tokens{
                {
                    Type:  hclsyntax.TokenOQuote,
                    Bytes: []byte(`"`),
                },
                {
                    Type:  hclsyntax.TokenCQuote,
                    Bytes: []byte(`"`),
                },
            },
        },
        {
            cty.StringVal("foo"),
            Tokens{
                {
                    Type:  hclsyntax.TokenOQuote,
                    Bytes: []byte(`"`),
                },
                {
                    Type:  hclsyntax.TokenQuotedLit,
                    Bytes: []byte(`foo`),
                },
                {
                    Type:  hclsyntax.TokenCQuote,
                    Bytes: []byte(`"`),
                },
            },
        },
        {
            cty.StringVal(`"foo"`),
            Tokens{
                {
                    Type:  hclsyntax.TokenOQuote,
                    Bytes: []byte(`"`),
                },
                {
                    Type:  hclsyntax.TokenQuotedLit,
                    Bytes: []byte(`\"foo\"`),
                },
                {
                    Type:  hclsyntax.TokenCQuote,
                    Bytes: []byte(`"`),
                },
            },
        },
        {
            cty.StringVal("hello\nworld\n"),
            Tokens{
                {
                    Type:  hclsyntax.TokenOQuote,
                    Bytes: []byte(`"`),
                },
                {
                    Type:  hclsyntax.TokenQuotedLit,
                    Bytes: []byte(`hello\nworld\n`),
                },
                {
                    Type:  hclsyntax.TokenCQuote,
                    Bytes: []byte(`"`),
                },
            },
        },
        {
            cty.StringVal("hello\r\nworld\r\n"),
            Tokens{
                {
                    Type:  hclsyntax.TokenOQuote,
                    Bytes: []byte(`"`),
                },
                {
                    Type:  hclsyntax.TokenQuotedLit,
                    Bytes: []byte(`hello\r\nworld\r\n`),
                },
                {
                    Type:  hclsyntax.TokenCQuote,
                    Bytes: []byte(`"`),
                },
            },
        },
        {
            cty.StringVal(`what\what`),
            Tokens{
                {
                    Type:  hclsyntax.TokenOQuote,
                    Bytes: []byte(`"`),
                },
                {
                    Type:  hclsyntax.TokenQuotedLit,
                    Bytes: []byte(`what\\what`),
                },
                {
                    Type:  hclsyntax.TokenCQuote,
                    Bytes: []byte(`"`),
                },
            },
        },
        {
            cty.StringVal("𝄞"),
            Tokens{
                {
                    Type:  hclsyntax.TokenOQuote,
                    Bytes: []byte(`"`),
                },
                {
                    Type:  hclsyntax.TokenQuotedLit,
                    Bytes: []byte("𝄞"),
                },
                {
                    Type:  hclsyntax.TokenCQuote,
                    Bytes: []byte(`"`),
                },
            },
        },
        {
            cty.StringVal("👩🏾"),
            Tokens{
                {
                    Type:  hclsyntax.TokenOQuote,
                    Bytes: []byte(`"`),
                },
                {
                    Type:  hclsyntax.TokenQuotedLit,
                    Bytes: []byte(`👩🏾`),
                },
                {
                    Type:  hclsyntax.TokenCQuote,
                    Bytes: []byte(`"`),
                },
            },
        },
        {
            cty.EmptyTupleVal,
            Tokens{
                {
                    Type:  hclsyntax.TokenOBrack,
                    Bytes: []byte(`[`),
                },
                {
                    Type:  hclsyntax.TokenCBrack,
                    Bytes: []byte(`]`),
                },
            },
        },
        {
            cty.TupleVal([]cty.Value{cty.EmptyTupleVal}),
            Tokens{
                {
                    Type:  hclsyntax.TokenOBrack,
                    Bytes: []byte(`[`),
                },
                {
                    Type:  hclsyntax.TokenOBrack,
                    Bytes: []byte(`[`),
                },
                {
                    Type:  hclsyntax.TokenCBrack,
                    Bytes: []byte(`]`),
                },
                {
                    Type:  hclsyntax.TokenCBrack,
                    Bytes: []byte(`]`),
                },
            },
        },
        {
            cty.ListValEmpty(cty.String),
            Tokens{
                {
                    Type:  hclsyntax.TokenOBrack,
                    Bytes: []byte(`[`),
                },
                {
                    Type:  hclsyntax.TokenCBrack,
                    Bytes: []byte(`]`),
                },
            },
        },
        {
            cty.SetValEmpty(cty.Bool),
            Tokens{
                {
                    Type:  hclsyntax.TokenOBrack,
                    Bytes: []byte(`[`),
                },
                {
                    Type:  hclsyntax.TokenCBrack,
                    Bytes: []byte(`]`),
                },
            },
        },
        {
            cty.TupleVal([]cty.Value{cty.True}),
            Tokens{
                {
                    Type:  hclsyntax.TokenOBrack,
                    Bytes: []byte(`[`),
                },
                {
                    Type:  hclsyntax.TokenIdent,
                    Bytes: []byte(`true`),
                },
                {
                    Type:  hclsyntax.TokenCBrack,
                    Bytes: []byte(`]`),
                },
            },
        },
        {
            cty.TupleVal([]cty.Value{cty.True, cty.NumberIntVal(0)}),
            Tokens{
                {
                    Type:  hclsyntax.TokenOBrack,
                    Bytes: []byte(`[`),
                },
                {
                    Type:  hclsyntax.TokenIdent,
                    Bytes: []byte(`true`),
                },
                {
                    Type:  hclsyntax.TokenComma,
                    Bytes: []byte(`,`),
                },
                {
                    Type:         hclsyntax.TokenNumberLit,
                    Bytes:        []byte(`0`),
                    SpacesBefore: 1,
                },
                {
                    Type:  hclsyntax.TokenCBrack,
                    Bytes: []byte(`]`),
                },
            },
        },
        {
            cty.EmptyObjectVal,
            Tokens{
                {
                    Type:  hclsyntax.TokenOBrace,
                    Bytes: []byte(`{`),
                },
                {
                    Type:  hclsyntax.TokenCBrace,
                    Bytes: []byte(`}`),
                },
            },
        },
        {
            cty.MapValEmpty(cty.Bool),
            Tokens{
                {
                    Type:  hclsyntax.TokenOBrace,
                    Bytes: []byte(`{`),
                },
                {
                    Type:  hclsyntax.TokenCBrace,
                    Bytes: []byte(`}`),
                },
            },
        },
        {
            cty.ObjectVal(map[string]cty.Value{
                "foo": cty.True,
            }),
            Tokens{
                {
                    Type:  hclsyntax.TokenOBrace,
                    Bytes: []byte(`{`),
                },
                {
                    Type:  hclsyntax.TokenNewline,
                    Bytes: []byte("\n"),
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte(`foo`),
                    SpacesBefore: 2,
                },
                {
                    Type:         hclsyntax.TokenEqual,
                    Bytes:        []byte(`=`),
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte(`true`),
                    SpacesBefore: 1,
                },
                {
                    Type:  hclsyntax.TokenNewline,
                    Bytes: []byte("\n"),
                },
                {
                    Type:  hclsyntax.TokenCBrace,
                    Bytes: []byte(`}`),
                },
            },
        },
        {
            cty.ObjectVal(map[string]cty.Value{
                "foo": cty.True,
                "bar": cty.NumberIntVal(0),
            }),
            Tokens{
                {
                    Type:  hclsyntax.TokenOBrace,
                    Bytes: []byte(`{`),
                },
                {
                    Type:  hclsyntax.TokenNewline,
                    Bytes: []byte("\n"),
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte(`bar`),
                    SpacesBefore: 2,
                },
                {
                    Type:         hclsyntax.TokenEqual,
                    Bytes:        []byte(`=`),
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNumberLit,
                    Bytes:        []byte(`0`),
                    SpacesBefore: 1,
                },
                {
                    Type:  hclsyntax.TokenNewline,
                    Bytes: []byte("\n"),
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte(`foo`),
                    SpacesBefore: 2,
                },
                {
                    Type:         hclsyntax.TokenEqual,
                    Bytes:        []byte(`=`),
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte(`true`),
                    SpacesBefore: 1,
                },
                {
                    Type:  hclsyntax.TokenNewline,
                    Bytes: []byte("\n"),
                },
                {
                    Type:  hclsyntax.TokenCBrace,
                    Bytes: []byte(`}`),
                },
            },
        },
        {
            cty.ObjectVal(map[string]cty.Value{
                "foo bar": cty.True,
            }),
            Tokens{
                {
                    Type:  hclsyntax.TokenOBrace,
                    Bytes: []byte(`{`),
                },
                {
                    Type:  hclsyntax.TokenNewline,
                    Bytes: []byte("\n"),
                },
                {
                    Type:         hclsyntax.TokenOQuote,
                    Bytes:        []byte(`"`),
                    SpacesBefore: 2,
                },
                {
                    Type:  hclsyntax.TokenQuotedLit,
                    Bytes: []byte(`foo bar`),
                },
                {
                    Type:  hclsyntax.TokenCQuote,
                    Bytes: []byte(`"`),
                },
                {
                    Type:         hclsyntax.TokenEqual,
                    Bytes:        []byte(`=`),
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte(`true`),
                    SpacesBefore: 1,
                },
                {
                    Type:  hclsyntax.TokenNewline,
                    Bytes: []byte("\n"),
                },
                {
                    Type:  hclsyntax.TokenCBrace,
                    Bytes: []byte(`}`),
                },
            },
        },
    }

    for _, test := range tests {
        t.Run(test.Val.GoString(), func(t *testing.T) {
            got := TokensForValue(test.Val)

            if !cmp.Equal(got, test.Want) {
                diff := cmp.Diff(got, test.Want, cmp.Comparer(func(a, b []byte) bool {
                    return bytes.Equal(a, b)
                }))
                var gotBuf, wantBuf bytes.Buffer
                got.WriteTo(&gotBuf)
                test.Want.WriteTo(&wantBuf)
                t.Errorf(
                    "wrong result\nvalue: %#v\ngot:   %s\nwant:  %s\ndiff:  %s",
                    test.Val, gotBuf.String(), wantBuf.String(), diff,
                )
            }
        })
    }
}

func TestTokensForTraversal(t *testing.T) {
    tests := []struct {
        Val  hcl.Traversal
        Want Tokens
    }{
        {
            hcl.Traversal{
                hcl.TraverseRoot{Name: "root"},
                hcl.TraverseAttr{Name: "attr"},
                hcl.TraverseIndex{Key: cty.StringVal("index")},
            },
            Tokens{
                {Type: hclsyntax.TokenIdent, Bytes: []byte("root")},
                {Type: hclsyntax.TokenDot, Bytes: []byte(".")},
                {Type: hclsyntax.TokenIdent, Bytes: []byte("attr")},
                {Type: hclsyntax.TokenOBrack, Bytes: []byte{'['}},
                {Type: hclsyntax.TokenOQuote, Bytes: []byte(`"`)},
                {Type: hclsyntax.TokenQuotedLit, Bytes: []byte("index")},
                {Type: hclsyntax.TokenCQuote, Bytes: []byte(`"`)},
                {Type: hclsyntax.TokenCBrack, Bytes: []byte{']'}},
            },
        },
    }

    for _, test := range tests {
        got := TokensForTraversal(test.Val)

        if !cmp.Equal(got, test.Want) {
            diff := cmp.Diff(got, test.Want, cmp.Comparer(func(a, b []byte) bool {
                return bytes.Equal(a, b)
            }))
            var gotBuf, wantBuf bytes.Buffer
            got.WriteTo(&gotBuf)
            test.Want.WriteTo(&wantBuf)
            t.Errorf(
                "wrong result\nvalue: %#v\ngot:   %s\nwant:  %s\ndiff:  %s",
                test.Val, gotBuf.String(), wantBuf.String(), diff,
            )
        }
    }
}

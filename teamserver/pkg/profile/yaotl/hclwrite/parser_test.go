package hclwrite

import (
    "fmt"
    "reflect"
    "testing"

    "github.com/davecgh/go-spew/spew"

    "github.com/google/go-cmp/cmp"

    "github.com/kylelemons/godebug/pretty"

    "Havoc/pkg/profile/yaotl"
    "Havoc/pkg/profile/yaotl/hclsyntax"
)

func TestParse(t *testing.T) {
    tests := []struct {
        src  string
        want TestTreeNode
    }{
        {
            "",
            TestTreeNode{
                Type: "Body",
            },
        },
        {
            "a = 1\n",
            TestTreeNode{
                Type: "Body",
                Children: []TestTreeNode{
                    {
                        Type: "Attribute",
                        Children: []TestTreeNode{
                            {
                                Type: "comments",
                            },
                            {
                                Type: "identifier",
                                Val:  "a",
                            },
                            {
                                Type: "Tokens",
                                Val:  " =",
                            },
                            {
                                Type: "Expression",
                                Children: []TestTreeNode{
                                    {
                                        Type: "Tokens",
                                        Val:  " 1",
                                    },
                                },
                            },
                            {
                                Type: "comments",
                            },
                            {
                                Type: "Tokens",
                                Val:  "\n",
                            },
                        },
                    },
                },
            },
        },
        {
            "# aye aye aye\na = 1\n",
            TestTreeNode{
                Type: "Body",
                Children: []TestTreeNode{
                    {
                        Type: "Attribute",
                        Children: []TestTreeNode{
                            {
                                Type: "comments",
                                Val:  "# aye aye aye\n",
                            },
                            {
                                Type: "identifier",
                                Val:  "a",
                            },
                            {
                                Type: "Tokens",
                                Val:  " =",
                            },
                            {
                                Type: "Expression",
                                Children: []TestTreeNode{
                                    {
                                        Type: "Tokens",
                                        Val:  " 1",
                                    },
                                },
                            },
                            {
                                Type: "comments",
                            },
                            {
                                Type: "Tokens",
                                Val:  "\n",
                            },
                        },
                    },
                },
            },
        },
        {
            "a = 1 # because it is\n",
            TestTreeNode{
                Type: "Body",
                Children: []TestTreeNode{
                    {
                        Type: "Attribute",
                        Children: []TestTreeNode{
                            {
                                Type: "comments",
                            },
                            {
                                Type: "identifier",
                                Val:  "a",
                            },
                            {
                                Type: "Tokens",
                                Val:  " =",
                            },
                            {
                                Type: "Expression",
                                Children: []TestTreeNode{
                                    {
                                        Type: "Tokens",
                                        Val:  " 1",
                                    },
                                },
                            },
                            {
                                Type: "comments",
                                Val:  " # because it is\n",
                            },
                        },
                    },
                },
            },
        },
        {
            "# bee bee bee\n\nb = 1\n", // two newlines separate the comment from the attribute
            TestTreeNode{
                Type: "Body",
                Children: []TestTreeNode{
                    {
                        Type: "Tokens", // Only lead/line comments attached to an object have type "comments"
                        Val:  "# bee bee bee\n\n",
                    },
                    {
                        Type: "Attribute",
                        Children: []TestTreeNode{
                            {
                                Type: "comments",
                            },
                            {
                                Type: "identifier",
                                Val:  "b",
                            },
                            {
                                Type: "Tokens",
                                Val:  " =",
                            },
                            {
                                Type: "Expression",
                                Children: []TestTreeNode{
                                    {
                                        Type: "Tokens",
                                        Val:  " 1",
                                    },
                                },
                            },
                            {
                                Type: "comments",
                                Val:  "",
                            },
                            {
                                Type: "Tokens",
                                Val:  "\n",
                            },
                        },
                    },
                },
            },
        },
        {
            "a = (\n  1 + 2\n)\nb = 3\n",
            TestTreeNode{
                Type: "Body",
                Children: []TestTreeNode{
                    {
                        Type: "Attribute",
                        Children: []TestTreeNode{
                            {Type: "comments"},
                            {
                                Type: "identifier",
                                Val:  "a",
                            },
                            {
                                Type: "Tokens",
                                Val:  " =",
                            },
                            {
                                Type: "Expression",
                                Children: []TestTreeNode{
                                    {
                                        Type: "Tokens",
                                        Val:  " (\n  1 + 2\n)",
                                    },
                                },
                            },
                            {Type: "comments"},
                            {
                                Type: "Tokens",
                                Val:  "\n",
                            },
                        },
                    },
                    {
                        Type: "Attribute",
                        Children: []TestTreeNode{
                            {Type: "comments"},
                            {
                                Type: "identifier",
                                Val:  "b",
                            },
                            {
                                Type: "Tokens",
                                Val:  " =",
                            },
                            {
                                Type: "Expression",
                                Children: []TestTreeNode{
                                    {
                                        Type: "Tokens",
                                        Val:  " 3",
                                    },
                                },
                            },
                            {Type: "comments"},
                            {
                                Type: "Tokens",
                                Val:  "\n",
                            },
                        },
                    },
                },
            },
        },
        {
            "b {}\n",
            TestTreeNode{
                Type: "Body",
                Children: []TestTreeNode{
                    {
                        Type: "Block",
                        Children: []TestTreeNode{
                            {
                                Type: "comments",
                            },
                            {
                                Type: "identifier",
                                Val:  "b",
                            },
                            {
                                Type: "blockLabels",
                            },
                            {
                                Type: "Tokens",
                                Val:  " {",
                            },
                            {
                                Type: "Body",
                            },
                            {
                                Type: "Tokens",
                                Val:  "}",
                            },
                            {
                                Type: "Tokens",
                                Val:  "\n",
                            },
                        },
                    },
                },
            },
        },
        {
            "b label {}\n",
            TestTreeNode{
                Type: "Body",
                Children: []TestTreeNode{
                    {
                        Type: "Block",
                        Children: []TestTreeNode{
                            {
                                Type: "comments",
                            },
                            {
                                Type: "identifier",
                                Val:  "b",
                            },
                            {
                                Type: "blockLabels",
                                Children: []TestTreeNode{
                                    {
                                        Type: "identifier",
                                        Val:  " label",
                                    },
                                },
                            },
                            {
                                Type: "Tokens",
                                Val:  " {",
                            },
                            {
                                Type: "Body",
                            },
                            {
                                Type: "Tokens",
                                Val:  "}",
                            },
                            {
                                Type: "Tokens",
                                Val:  "\n",
                            },
                        },
                    },
                },
            },
        },
        {
            "b \"label\" {}\n",
            TestTreeNode{
                Type: "Body",
                Children: []TestTreeNode{
                    {
                        Type: "Block",
                        Children: []TestTreeNode{
                            {
                                Type: "comments",
                            },
                            {
                                Type: "identifier",
                                Val:  "b",
                            },
                            {
                                Type: "blockLabels",
                                Children: []TestTreeNode{
                                    {
                                        Type: "quoted",
                                        Val:  ` "label"`,
                                    },
                                },
                            },
                            {
                                Type: "Tokens",
                                Val:  " {",
                            },
                            {
                                Type: "Body",
                            },
                            {
                                Type: "Tokens",
                                Val:  "}",
                            },
                            {
                                Type: "Tokens",
                                Val:  "\n",
                            },
                        },
                    },
                },
            },
        },
        {
            "b \"label1\" /* foo */ \"label2\" {}\n",
            TestTreeNode{
                Type: "Body",
                Children: []TestTreeNode{
                    {
                        Type: "Block",
                        Children: []TestTreeNode{
                            {
                                Type: "comments",
                            },
                            {
                                Type: "identifier",
                                Val:  "b",
                            },
                            {
                                Type: "blockLabels",
                                Children: []TestTreeNode{
                                    {
                                        Type: "quoted",
                                        Val:  ` "label1"`,
                                    },
                                    {
                                        // The comment between the labels just
                                        // becomes an "unstructured tokens"
                                        // node, because this isn't a place
                                        // where we expect comments to attach
                                        // to a particular object as
                                        // documentation.
                                        Type: "Tokens",
                                        Val:  ` /* foo */`,
                                    },
                                    {
                                        Type: "quoted",
                                        Val:  ` "label2"`,
                                    },
                                },
                            },
                            {
                                Type: "Tokens",
                                Val:  " {",
                            },
                            {
                                Type: "Body",
                            },
                            {
                                Type: "Tokens",
                                Val:  "}",
                            },
                            {
                                Type: "Tokens",
                                Val:  "\n",
                            },
                        },
                    },
                },
            },
        },
        {
            "b {\n  a = 1\n}\n",
            TestTreeNode{
                Type: "Body",
                Children: []TestTreeNode{
                    {
                        Type: "Block",
                        Children: []TestTreeNode{
                            {
                                Type: "comments",
                            },
                            {
                                Type: "identifier",
                                Val:  "b",
                            },
                            {
                                Type: "blockLabels",
                            },
                            {
                                Type: "Tokens",
                                Val:  " {",
                            },
                            {
                                Type: "Body",
                                Children: []TestTreeNode{
                                    {
                                        Type: "Tokens",
                                        Val:  "\n",
                                    },
                                    {
                                        Type: "Attribute",
                                        Children: []TestTreeNode{
                                            {
                                                Type: "comments",
                                            },
                                            {
                                                Type: "identifier",
                                                Val:  "  a",
                                            },
                                            {
                                                Type: "Tokens",
                                                Val:  " =",
                                            },
                                            {
                                                Type: "Expression",
                                                Children: []TestTreeNode{
                                                    {
                                                        Type: "Tokens",
                                                        Val:  " 1",
                                                    },
                                                },
                                            },
                                            {
                                                Type: "comments",
                                            },
                                            {
                                                Type: "Tokens",
                                                Val:  "\n",
                                            },
                                        },
                                    },
                                },
                            },
                            {
                                Type: "Tokens",
                                Val:  "}",
                            },
                            {
                                Type: "Tokens",
                                Val:  "\n",
                            },
                        },
                    },
                },
            },
        },
        {
            "a = foo\n",
            TestTreeNode{
                Type: "Body",
                Children: []TestTreeNode{
                    {
                        Type: "Attribute",
                        Children: []TestTreeNode{
                            {
                                Type: "comments",
                            },
                            {
                                Type: "identifier",
                                Val:  "a",
                            },
                            {
                                Type: "Tokens",
                                Val:  " =",
                            },
                            {
                                Type: "Expression",
                                Children: []TestTreeNode{
                                    {
                                        Type: "Traversal",
                                        Children: []TestTreeNode{
                                            {
                                                Type: "TraverseName",
                                                Children: []TestTreeNode{
                                                    {
                                                        Type: "identifier",
                                                        Val:  " foo",
                                                    },
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                            {
                                Type: "comments",
                            },
                            {
                                Type: "Tokens",
                                Val:  "\n",
                            },
                        },
                    },
                },
            },
        },
        {
            "a = foo.bar\n",
            TestTreeNode{
                Type: "Body",
                Children: []TestTreeNode{
                    {
                        Type: "Attribute",
                        Children: []TestTreeNode{
                            {
                                Type: "comments",
                            },
                            {
                                Type: "identifier",
                                Val:  "a",
                            },
                            {
                                Type: "Tokens",
                                Val:  " =",
                            },
                            {
                                Type: "Expression",
                                Children: []TestTreeNode{
                                    {
                                        Type: "Traversal",
                                        Children: []TestTreeNode{
                                            {
                                                Type: "TraverseName",
                                                Children: []TestTreeNode{
                                                    {
                                                        Type: "identifier",
                                                        Val:  " foo",
                                                    },
                                                },
                                            },
                                            {
                                                Type: "TraverseName",
                                                Children: []TestTreeNode{
                                                    {
                                                        Type: "Tokens",
                                                        Val:  ".",
                                                    },
                                                    {
                                                        Type: "identifier",
                                                        Val:  "bar",
                                                    },
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                            {
                                Type: "comments",
                            },
                            {
                                Type: "Tokens",
                                Val:  "\n",
                            },
                        },
                    },
                },
            },
        },
        {
            "a = foo[0]\n",
            TestTreeNode{
                Type: "Body",
                Children: []TestTreeNode{
                    {
                        Type: "Attribute",
                        Children: []TestTreeNode{
                            {
                                Type: "comments",
                            },
                            {
                                Type: "identifier",
                                Val:  "a",
                            },
                            {
                                Type: "Tokens",
                                Val:  " =",
                            },
                            {
                                Type: "Expression",
                                Children: []TestTreeNode{
                                    {
                                        Type: "Traversal",
                                        Children: []TestTreeNode{
                                            {
                                                Type: "TraverseName",
                                                Children: []TestTreeNode{
                                                    {
                                                        Type: "identifier",
                                                        Val:  " foo",
                                                    },
                                                },
                                            },
                                            {
                                                Type: "TraverseIndex",
                                                Children: []TestTreeNode{
                                                    {
                                                        Type: "Tokens",
                                                        Val:  "[",
                                                    },
                                                    {
                                                        Type: "number",
                                                        Val:  "0",
                                                    },
                                                    {
                                                        Type: "Tokens",
                                                        Val:  "]",
                                                    },
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                            {
                                Type: "comments",
                            },
                            {
                                Type: "Tokens",
                                Val:  "\n",
                            },
                        },
                    },
                },
            },
        },
        {
            "a = foo.0\n",
            TestTreeNode{
                Type: "Body",
                Children: []TestTreeNode{
                    {
                        Type: "Attribute",
                        Children: []TestTreeNode{
                            {
                                Type: "comments",
                            },
                            {
                                Type: "identifier",
                                Val:  "a",
                            },
                            {
                                Type: "Tokens",
                                Val:  " =",
                            },
                            {
                                Type: "Expression",
                                Children: []TestTreeNode{
                                    {
                                        Type: "Traversal",
                                        Children: []TestTreeNode{
                                            {
                                                Type: "TraverseName",
                                                Children: []TestTreeNode{
                                                    {
                                                        Type: "identifier",
                                                        Val:  " foo",
                                                    },
                                                },
                                            },
                                            {
                                                Type: "TraverseIndex",
                                                Children: []TestTreeNode{
                                                    {
                                                        Type: "Tokens",
                                                        Val:  ".",
                                                    },
                                                    {
                                                        Type: "number",
                                                        Val:  "0",
                                                    },
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                            {
                                Type: "comments",
                            },
                            {
                                Type: "Tokens",
                                Val:  "\n",
                            },
                        },
                    },
                },
            },
        },
        {
            "a = foo.*\n",
            TestTreeNode{
                Type: "Body",
                Children: []TestTreeNode{
                    {
                        Type: "Attribute",
                        Children: []TestTreeNode{
                            {
                                Type: "comments",
                            },
                            {
                                Type: "identifier",
                                Val:  "a",
                            },
                            {
                                Type: "Tokens",
                                Val:  " =",
                            },
                            {
                                Type: "Expression",
                                Children: []TestTreeNode{
                                    {
                                        Type: "Traversal",
                                        Children: []TestTreeNode{
                                            {
                                                Type: "TraverseName",
                                                Children: []TestTreeNode{
                                                    {
                                                        Type: "identifier",
                                                        Val:  " foo",
                                                    },
                                                },
                                            },
                                        },
                                    },
                                    {
                                        Type: "Tokens",
                                        Val:  ".*",
                                    },
                                },
                            },
                            {
                                Type: "comments",
                            },
                            {
                                Type: "Tokens",
                                Val:  "\n",
                            },
                        },
                    },
                },
            },
        },
        {
            "a = foo.*.bar\n",
            TestTreeNode{
                Type: "Body",
                Children: []TestTreeNode{
                    {
                        Type: "Attribute",
                        Children: []TestTreeNode{
                            {
                                Type: "comments",
                            },
                            {
                                Type: "identifier",
                                Val:  "a",
                            },
                            {
                                Type: "Tokens",
                                Val:  " =",
                            },
                            {
                                Type: "Expression",
                                Children: []TestTreeNode{
                                    {
                                        Type: "Traversal",
                                        Children: []TestTreeNode{
                                            {
                                                Type: "TraverseName",
                                                Children: []TestTreeNode{
                                                    {
                                                        Type: "identifier",
                                                        Val:  " foo",
                                                    },
                                                },
                                            },
                                        },
                                    },
                                    {
                                        Type: "Tokens",
                                        Val:  ".*.bar",
                                    },
                                },
                            },
                            {
                                Type: "comments",
                            },
                            {
                                Type: "Tokens",
                                Val:  "\n",
                            },
                        },
                    },
                },
            },
        },
        {
            "a = foo[*]\n",
            TestTreeNode{
                Type: "Body",
                Children: []TestTreeNode{
                    {
                        Type: "Attribute",
                        Children: []TestTreeNode{
                            {
                                Type: "comments",
                            },
                            {
                                Type: "identifier",
                                Val:  "a",
                            },
                            {
                                Type: "Tokens",
                                Val:  " =",
                            },
                            {
                                Type: "Expression",
                                Children: []TestTreeNode{
                                    {
                                        Type: "Traversal",
                                        Children: []TestTreeNode{
                                            {
                                                Type: "TraverseName",
                                                Children: []TestTreeNode{
                                                    {
                                                        Type: "identifier",
                                                        Val:  " foo",
                                                    },
                                                },
                                            },
                                        },
                                    },
                                    {
                                        Type: "Tokens",
                                        Val:  "[*]",
                                    },
                                },
                            },
                            {
                                Type: "comments",
                            },
                            {
                                Type: "Tokens",
                                Val:  "\n",
                            },
                        },
                    },
                },
            },
        },
        {
            "a = foo[*].bar\n",
            TestTreeNode{
                Type: "Body",
                Children: []TestTreeNode{
                    {
                        Type: "Attribute",
                        Children: []TestTreeNode{
                            {
                                Type: "comments",
                            },
                            {
                                Type: "identifier",
                                Val:  "a",
                            },
                            {
                                Type: "Tokens",
                                Val:  " =",
                            },
                            {
                                Type: "Expression",
                                Children: []TestTreeNode{
                                    {
                                        Type: "Traversal",
                                        Children: []TestTreeNode{
                                            {
                                                Type: "TraverseName",
                                                Children: []TestTreeNode{
                                                    {
                                                        Type: "identifier",
                                                        Val:  " foo",
                                                    },
                                                },
                                            },
                                        },
                                    },
                                    {
                                        Type: "Tokens",
                                        Val:  "[*].bar",
                                    },
                                },
                            },
                            {
                                Type: "comments",
                            },
                            {
                                Type: "Tokens",
                                Val:  "\n",
                            },
                        },
                    },
                },
            },
        },
        {
            "a = foo[bar]\n",
            TestTreeNode{
                Type: "Body",
                Children: []TestTreeNode{
                    {
                        Type: "Attribute",
                        Children: []TestTreeNode{
                            {
                                Type: "comments",
                            },
                            {
                                Type: "identifier",
                                Val:  "a",
                            },
                            {
                                Type: "Tokens",
                                Val:  " =",
                            },
                            {
                                Type: "Expression",
                                Children: []TestTreeNode{
                                    {
                                        Type: "Traversal",
                                        Children: []TestTreeNode{
                                            {
                                                Type: "TraverseName",
                                                Children: []TestTreeNode{
                                                    {
                                                        Type: "identifier",
                                                        Val:  " foo",
                                                    },
                                                },
                                            },
                                        },
                                    },
                                    {
                                        Type: "Tokens",
                                        Val:  "[",
                                    },
                                    {
                                        Type: "Traversal",
                                        Children: []TestTreeNode{
                                            {
                                                Type: "TraverseName",
                                                Children: []TestTreeNode{
                                                    {
                                                        Type: "identifier",
                                                        Val:  "bar",
                                                    },
                                                },
                                            },
                                        },
                                    },
                                    {
                                        Type: "Tokens",
                                        Val:  "]",
                                    },
                                },
                            },
                            {
                                Type: "comments",
                            },
                            {
                                Type: "Tokens",
                                Val:  "\n",
                            },
                        },
                    },
                },
            },
        },
        {
            "a = foo[bar.baz]\n",
            TestTreeNode{
                Type: "Body",
                Children: []TestTreeNode{
                    {
                        Type: "Attribute",
                        Children: []TestTreeNode{
                            {
                                Type: "comments",
                            },
                            {
                                Type: "identifier",
                                Val:  "a",
                            },
                            {
                                Type: "Tokens",
                                Val:  " =",
                            },
                            {
                                Type: "Expression",
                                Children: []TestTreeNode{
                                    {
                                        Type: "Traversal",
                                        Children: []TestTreeNode{
                                            {
                                                Type: "TraverseName",
                                                Children: []TestTreeNode{
                                                    {
                                                        Type: "identifier",
                                                        Val:  " foo",
                                                    },
                                                },
                                            },
                                        },
                                    },
                                    {
                                        Type: "Tokens",
                                        Val:  "[",
                                    },
                                    {
                                        Type: "Traversal",
                                        Children: []TestTreeNode{
                                            {
                                                Type: "TraverseName",
                                                Children: []TestTreeNode{
                                                    {
                                                        Type: "identifier",
                                                        Val:  "bar",
                                                    },
                                                },
                                            },
                                            {
                                                Type: "TraverseName",
                                                Children: []TestTreeNode{
                                                    {
                                                        Type: "Tokens",
                                                        Val:  ".",
                                                    },
                                                    {
                                                        Type: "identifier",
                                                        Val:  "baz",
                                                    },
                                                },
                                            },
                                        },
                                    },
                                    {
                                        Type: "Tokens",
                                        Val:  "]",
                                    },
                                },
                            },
                            {
                                Type: "comments",
                            },
                            {
                                Type: "Tokens",
                                Val:  "\n",
                            },
                        },
                    },
                },
            },
        },
        {
            "a = foo[bar].baz\n",
            TestTreeNode{
                Type: "Body",
                Children: []TestTreeNode{
                    {
                        Type: "Attribute",
                        Children: []TestTreeNode{
                            {
                                Type: "comments",
                            },
                            {
                                Type: "identifier",
                                Val:  "a",
                            },
                            {
                                Type: "Tokens",
                                Val:  " =",
                            },
                            {
                                Type: "Expression",
                                Children: []TestTreeNode{
                                    {
                                        Type: "Traversal",
                                        Children: []TestTreeNode{
                                            {
                                                Type: "TraverseName",
                                                Children: []TestTreeNode{
                                                    {
                                                        Type: "identifier",
                                                        Val:  " foo",
                                                    },
                                                },
                                            },
                                        },
                                    },
                                    {
                                        Type: "Tokens",
                                        Val:  "[",
                                    },
                                    {
                                        Type: "Traversal",
                                        Children: []TestTreeNode{
                                            {
                                                Type: "TraverseName",
                                                Children: []TestTreeNode{
                                                    {
                                                        Type: "identifier",
                                                        Val:  "bar",
                                                    },
                                                },
                                            },
                                        },
                                    },
                                    {
                                        Type: "Tokens",
                                        Val:  "].baz",
                                    },
                                },
                            },
                            {
                                Type: "comments",
                            },
                            {
                                Type: "Tokens",
                                Val:  "\n",
                            },
                        },
                    },
                },
            },
        },
    }

    for _, test := range tests {
        t.Run(test.src, func(t *testing.T) {
            file, diags := parse([]byte(test.src), "", hcl.Pos{Line: 1, Column: 1})
            if len(diags) > 0 {
                for _, diag := range diags {
                    t.Logf(" - %s", diag.Error())
                }
                t.Fatalf("unexpected diagnostics")
            }

            got := makeTestTree(file.body)

            if !cmp.Equal(got, test.want) {
                diff := cmp.Diff(got, test.want)
                t.Errorf(
                    "wrong result\ninput:\n%s\n\ngot:\n%s\nwant:%s\n\ndiff:\n%s",
                    test.src,
                    spew.Sdump(got),
                    spew.Sdump(test.want),
                    diff,
                )
            }
        })
    }
}

func TestPartitionTokens(t *testing.T) {
    tests := []struct {
        tokens    hclsyntax.Tokens
        rng       hcl.Range
        wantStart int
        wantEnd   int
    }{
        {
            hclsyntax.Tokens{},
            hcl.Range{
                Start: hcl.Pos{Byte: 0},
                End:   hcl.Pos{Byte: 0},
            },
            0,
            0,
        },
        {
            hclsyntax.Tokens{
                {
                    Type: hclsyntax.TokenIdent,
                    Range: hcl.Range{
                        Start: hcl.Pos{Byte: 0},
                        End:   hcl.Pos{Byte: 4},
                    },
                },
            },
            hcl.Range{
                Start: hcl.Pos{Byte: 0},
                End:   hcl.Pos{Byte: 4},
            },
            0,
            1,
        },
        {
            hclsyntax.Tokens{
                {
                    Type: hclsyntax.TokenIdent,
                    Range: hcl.Range{
                        Start: hcl.Pos{Byte: 0},
                        End:   hcl.Pos{Byte: 4},
                    },
                },
                {
                    Type: hclsyntax.TokenIdent,
                    Range: hcl.Range{
                        Start: hcl.Pos{Byte: 4},
                        End:   hcl.Pos{Byte: 8},
                    },
                },
                {
                    Type: hclsyntax.TokenIdent,
                    Range: hcl.Range{
                        Start: hcl.Pos{Byte: 8},
                        End:   hcl.Pos{Byte: 12},
                    },
                },
            },
            hcl.Range{
                Start: hcl.Pos{Byte: 4},
                End:   hcl.Pos{Byte: 8},
            },
            1,
            2,
        },
        {
            hclsyntax.Tokens{
                {
                    Type: hclsyntax.TokenIdent,
                    Range: hcl.Range{
                        Start: hcl.Pos{Byte: 0},
                        End:   hcl.Pos{Byte: 4},
                    },
                },
                {
                    Type: hclsyntax.TokenIdent,
                    Range: hcl.Range{
                        Start: hcl.Pos{Byte: 4},
                        End:   hcl.Pos{Byte: 8},
                    },
                },
                {
                    Type: hclsyntax.TokenIdent,
                    Range: hcl.Range{
                        Start: hcl.Pos{Byte: 8},
                        End:   hcl.Pos{Byte: 12},
                    },
                },
            },
            hcl.Range{
                Start: hcl.Pos{Byte: 0},
                End:   hcl.Pos{Byte: 8},
            },
            0,
            2,
        },
        {
            hclsyntax.Tokens{
                {
                    Type: hclsyntax.TokenIdent,
                    Range: hcl.Range{
                        Start: hcl.Pos{Byte: 0},
                        End:   hcl.Pos{Byte: 4},
                    },
                },
                {
                    Type: hclsyntax.TokenIdent,
                    Range: hcl.Range{
                        Start: hcl.Pos{Byte: 4},
                        End:   hcl.Pos{Byte: 8},
                    },
                },
                {
                    Type: hclsyntax.TokenIdent,
                    Range: hcl.Range{
                        Start: hcl.Pos{Byte: 8},
                        End:   hcl.Pos{Byte: 12},
                    },
                },
            },
            hcl.Range{
                Start: hcl.Pos{Byte: 4},
                End:   hcl.Pos{Byte: 12},
            },
            1,
            3,
        },
    }

    prettyConfig := &pretty.Config{
        Diffable:          true,
        IncludeUnexported: true,
        PrintStringers:    true,
    }

    for i, test := range tests {
        t.Run(fmt.Sprintf("%02d", i), func(t *testing.T) {
            gotStart, gotEnd := partitionTokens(test.tokens, test.rng)

            if gotStart != test.wantStart || gotEnd != test.wantEnd {
                t.Errorf(
                    "wrong result\ntokens: %s\nrange: %#v\ngot:   %d, %d\nwant:  %d, %d",
                    prettyConfig.Sprint(test.tokens), test.rng,
                    gotStart, test.wantStart,
                    gotEnd, test.wantEnd,
                )
            }
        })
    }
}

func TestPartitionLeadCommentTokens(t *testing.T) {
    tests := []struct {
        tokens    hclsyntax.Tokens
        wantStart int
    }{
        {
            hclsyntax.Tokens{},
            0,
        },
        {
            hclsyntax.Tokens{
                {
                    Type: hclsyntax.TokenComment,
                },
            },
            0,
        },
        {
            hclsyntax.Tokens{
                {
                    Type: hclsyntax.TokenComment,
                },
                {
                    Type: hclsyntax.TokenComment,
                },
            },
            0,
        },
        {
            hclsyntax.Tokens{
                {
                    Type: hclsyntax.TokenComment,
                },
                {
                    Type: hclsyntax.TokenNewline,
                },
            },
            2,
        },
        {
            hclsyntax.Tokens{
                {
                    Type: hclsyntax.TokenComment,
                },
                {
                    Type: hclsyntax.TokenNewline,
                },
                {
                    Type: hclsyntax.TokenComment,
                },
            },
            2,
        },
    }

    prettyConfig := &pretty.Config{
        Diffable:          true,
        IncludeUnexported: true,
        PrintStringers:    true,
    }

    for i, test := range tests {
        t.Run(fmt.Sprintf("%02d", i), func(t *testing.T) {
            gotStart := partitionLeadCommentTokens(test.tokens)

            if gotStart != test.wantStart {
                t.Errorf(
                    "wrong result\ntokens: %s\ngot:   %d\nwant:  %d",
                    prettyConfig.Sprint(test.tokens),
                    gotStart, test.wantStart,
                )
            }
        })
    }
}

func TestLexConfig(t *testing.T) {
    tests := []struct {
        input string
        want  Tokens
    }{
        {
            `a  b `,
            Tokens{
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte(`a`),
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte(`b`),
                    SpacesBefore: 2,
                },
                {
                    Type:         hclsyntax.TokenEOF,
                    Bytes:        []byte{},
                    SpacesBefore: 1,
                },
            },
        },
        {
            `
foo "bar" "baz" {
    pizza = " cheese "
}
`,
            Tokens{
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
                    Bytes:        []byte(`{`),
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte("\n"),
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenIdent,
                    Bytes:        []byte(`pizza`),
                    SpacesBefore: 4,
                },
                {
                    Type:         hclsyntax.TokenEqual,
                    Bytes:        []byte(`=`),
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenOQuote,
                    Bytes:        []byte(`"`),
                    SpacesBefore: 1,
                },
                {
                    Type:         hclsyntax.TokenQuotedLit,
                    Bytes:        []byte(` cheese `),
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenCQuote,
                    Bytes:        []byte(`"`),
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte("\n"),
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenCBrace,
                    Bytes:        []byte(`}`),
                    SpacesBefore: 0,
                },
                {
                    Type:         hclsyntax.TokenNewline,
                    Bytes:        []byte("\n"),
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

    prettyConfig := &pretty.Config{
        Diffable:          true,
        IncludeUnexported: true,
        PrintStringers:    true,
    }

    for _, test := range tests {
        t.Run(test.input, func(t *testing.T) {
            got := lexConfig([]byte(test.input))

            if !reflect.DeepEqual(got, test.want) {
                diff := prettyConfig.Compare(test.want, got)
                t.Errorf(
                    "wrong result\ninput: %s\ndiff:  %s", test.input, diff,
                )
            }
        })
    }
}

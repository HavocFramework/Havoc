package hclwrite_test

import (
    "fmt"

    "Havoc/pkg/profile/yaotl"
    "Havoc/pkg/profile/yaotl/hclwrite"
    "github.com/zclconf/go-cty/cty"
)

func Example_generateFromScratch() {
    f := hclwrite.NewEmptyFile()
    rootBody := f.Body()
    rootBody.SetAttributeValue("string", cty.StringVal("bar")) // this is overwritten later
    rootBody.AppendNewline()
    rootBody.SetAttributeValue("object", cty.ObjectVal(map[string]cty.Value{
        "foo": cty.StringVal("foo"),
        "bar": cty.NumberIntVal(5),
        "baz": cty.True,
    }))
    rootBody.SetAttributeValue("string", cty.StringVal("foo"))
    rootBody.SetAttributeValue("bool", cty.False)
    rootBody.SetAttributeTraversal("path", hcl.Traversal{
        hcl.TraverseRoot{
            Name: "env",
        },
        hcl.TraverseAttr{
            Name: "PATH",
        },
    })
    rootBody.AppendNewline()
    fooBlock := rootBody.AppendNewBlock("foo", nil)
    fooBody := fooBlock.Body()
    rootBody.AppendNewBlock("empty", nil)
    rootBody.AppendNewline()
    barBlock := rootBody.AppendNewBlock("bar", []string{"a", "b"})
    barBody := barBlock.Body()

    fooBody.SetAttributeValue("hello", cty.StringVal("world"))

    bazBlock := barBody.AppendNewBlock("baz", nil)
    bazBody := bazBlock.Body()
    bazBody.SetAttributeValue("foo", cty.NumberIntVal(10))
    bazBody.SetAttributeValue("beep", cty.StringVal("boop"))
    bazBody.SetAttributeValue("baz", cty.ListValEmpty(cty.String))

    fmt.Printf("%s", f.Bytes())
    // Output:
    // string = "foo"
    //
    // object = {
    //   bar = 5
    //   baz = true
    //   foo = "foo"
    // }
    // bool = false
    // path = env.PATH
    //
    // foo {
    //   hello = "world"
    // }
    // empty {
    // }
    //
    // bar "a" "b" {
    //   baz {
    //     foo  = 10
    //     beep = "boop"
    //     baz  = []
    //   }
    // }
}

func ExampleExpression_RenameVariablePrefix() {
    src := []byte(
        "foo = a.x + a.y * b.c\n" +
            "bar = max(a.z, b.c)\n",
    )
    f, diags := hclwrite.ParseConfig(src, "", hcl.Pos{Line: 1, Column: 1})
    if diags.HasErrors() {
        fmt.Printf("errors: %s", diags)
        return
    }

    // Rename references of variable "a" to "z"
    for _, attr := range f.Body().Attributes() {
        attr.Expr().RenameVariablePrefix(
            []string{"a"},
            []string{"z"},
        )
    }

    fmt.Printf("%s", f.Bytes())
    // Output:
    // foo = z.x + z.y * b.c
    // bar = max(z.z, b.c)
}

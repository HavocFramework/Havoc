package dynblock

import (
    "reflect"
    "testing"

    "Havoc/pkg/profile/yaotl/hcldec"
    "github.com/zclconf/go-cty/cty"

    "github.com/davecgh/go-spew/spew"

    "Havoc/pkg/profile/yaotl"
    "Havoc/pkg/profile/yaotl/hclsyntax"
)

func TestVariables(t *testing.T) {
    const src = `

# We have some references to things inside the "val" attribute inside each
# of our "b" blocks, which should be included in the result of WalkVariables
# but not WalkExpandVariables.

a {
  dynamic "b" {
    for_each = [for i, v in some_list_0: "${i}=${v},${baz}"]
    labels = ["${b.value} ${something_else_0}"]
    content {
      val = "${b.value} ${something_else_1}"
    }
  }
}

dynamic "a" {
  for_each = some_list_1

  content {
    b "foo" {
      val = "${a.value} ${something_else_2}"
    }

    dynamic "b" {
      for_each = some_list_2
      iterator = dyn_b
      labels = ["${a.value} ${dyn_b.value} ${b} ${something_else_3}"]
      content {
        val = "${a.value} ${dyn_b.value} ${something_else_4}"
      }
    }
  }
}

dynamic "a" {
  for_each = some_list_3
  iterator = dyn_a

  content {
    b "foo" {
      val = "${dyn_a.value} ${something_else_5}"
    }

    dynamic "b" {
      for_each = some_list_4
      labels = ["${dyn_a.value} ${b.value} ${a} ${something_else_6}"]
      content {
        val = "${dyn_a.value} ${b.value} ${something_else_7}"
      }
    }
  }
}
`

    f, diags := hclsyntax.ParseConfig([]byte(src), "", hcl.Pos{})
    if len(diags) != 0 {
        t.Errorf("unexpected diagnostics during parse")
        for _, diag := range diags {
            t.Logf("- %s", diag)
        }
        return
    }

    spec := &hcldec.BlockListSpec{
        TypeName: "a",
        Nested: &hcldec.BlockMapSpec{
            TypeName:   "b",
            LabelNames: []string{"key"},
            Nested: &hcldec.AttrSpec{
                Name: "val",
                Type: cty.String,
            },
        },
    }

    t.Run("WalkVariables", func(t *testing.T) {
        traversals := VariablesHCLDec(f.Body, spec)
        got := make([]string, len(traversals))
        for i, traversal := range traversals {
            got[i] = traversal.RootName()
        }

        // The block structure is traversed one level at a time, so the ordering
        // here is reflecting first a pass of the root, then the first child
        // under the root, then the first child under that, etc.
        want := []string{
            "some_list_1",
            "some_list_3",
            "some_list_0",
            "baz",
            "something_else_0",
            "something_else_1", // Would not be included for WalkExpandVariables because it only appears in content
            "some_list_2",
            "b", // This is correct because it is referenced in a context where the iterator is overridden to be dyn_b
            "something_else_3",
            "something_else_2", // Would not be included for WalkExpandVariables because it only appears in content
            "something_else_4", // Would not be included for WalkExpandVariables because it only appears in content
            "some_list_4",
            "a", // This is correct because it is referenced in a context where the iterator is overridden to be dyn_a
            "something_else_6",
            "something_else_5", // Would not be included for WalkExpandVariables because it only appears in content
            "something_else_7", // Would not be included for WalkExpandVariables because it only appears in content
        }

        if !reflect.DeepEqual(got, want) {
            t.Errorf("wrong result\ngot: %swant: %s", spew.Sdump(got), spew.Sdump(want))
        }
    })

    t.Run("WalkExpandVariables", func(t *testing.T) {
        traversals := ExpandVariablesHCLDec(f.Body, spec)
        got := make([]string, len(traversals))
        for i, traversal := range traversals {
            got[i] = traversal.RootName()
        }

        // The block structure is traversed one level at a time, so the ordering
        // here is reflecting first a pass of the root, then the first child
        // under the root, then the first child under that, etc.
        want := []string{
            "some_list_1",
            "some_list_3",
            "some_list_0",
            "baz",
            "something_else_0",
            "some_list_2",
            "b", // This is correct because it is referenced in a context where the iterator is overridden to be dyn_b
            "something_else_3",
            "some_list_4",
            "a", // This is correct because it is referenced in a context where the iterator is overridden to be dyn_a
            "something_else_6",
        }

        if !reflect.DeepEqual(got, want) {
            t.Errorf("wrong result\ngot: %swant: %s", spew.Sdump(got), spew.Sdump(want))
        }
    })
}

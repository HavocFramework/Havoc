package json

import (
    "fmt"
    "reflect"
    "strings"
    "testing"

    "github.com/davecgh/go-spew/spew"
    "github.com/go-test/deep"
    "Havoc/pkg/profile/yaotl"
    "github.com/zclconf/go-cty/cty"
)

func TestBodyPartialContent(t *testing.T) {
    tests := []struct {
        src       string
        schema    *hcl.BodySchema
        want      *hcl.BodyContent
        diagCount int
    }{
        {
            `{}`,
            &hcl.BodySchema{},
            &hcl.BodyContent{
                Attributes: map[string]*hcl.Attribute{},
                MissingItemRange: hcl.Range{
                    Filename: "test.json",
                    Start:    hcl.Pos{Line: 1, Column: 2, Byte: 1},
                    End:      hcl.Pos{Line: 1, Column: 3, Byte: 2},
                },
            },
            0,
        },
        {
            `[]`,
            &hcl.BodySchema{},
            &hcl.BodyContent{
                Attributes: map[string]*hcl.Attribute{},
                MissingItemRange: hcl.Range{
                    Filename: "test.json",
                    Start:    hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:      hcl.Pos{Line: 1, Column: 2, Byte: 1},
                },
            },
            0,
        },
        {
            `[{}]`,
            &hcl.BodySchema{},
            &hcl.BodyContent{
                Attributes: map[string]*hcl.Attribute{},
                MissingItemRange: hcl.Range{
                    Filename: "test.json",
                    Start:    hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:      hcl.Pos{Line: 1, Column: 2, Byte: 1},
                },
            },
            0,
        },
        {
            `[[]]`,
            &hcl.BodySchema{},
            &hcl.BodyContent{
                Attributes: map[string]*hcl.Attribute{},
                MissingItemRange: hcl.Range{
                    Filename: "test.json",
                    Start:    hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:      hcl.Pos{Line: 1, Column: 2, Byte: 1},
                },
            },
            1, // elements of root array must be objects
        },
        {
            `{"//": "comment that should be ignored"}`,
            &hcl.BodySchema{},
            &hcl.BodyContent{
                Attributes: map[string]*hcl.Attribute{},
                MissingItemRange: hcl.Range{
                    Filename: "test.json",
                    Start:    hcl.Pos{Line: 1, Column: 40, Byte: 39},
                    End:      hcl.Pos{Line: 1, Column: 41, Byte: 40},
                },
            },
            0,
        },
        {
            `{"//": "comment that should be ignored", "//": "another comment"}`,
            &hcl.BodySchema{},
            &hcl.BodyContent{
                Attributes: map[string]*hcl.Attribute{},
                MissingItemRange: hcl.Range{
                    Filename: "test.json",
                    Start:    hcl.Pos{Line: 1, Column: 65, Byte: 64},
                    End:      hcl.Pos{Line: 1, Column: 66, Byte: 65},
                },
            },
            0,
        },
        {
            `{"name":"Ermintrude"}`,
            &hcl.BodySchema{
                Attributes: []hcl.AttributeSchema{
                    {
                        Name: "name",
                    },
                },
            },
            &hcl.BodyContent{
                Attributes: map[string]*hcl.Attribute{
                    "name": &hcl.Attribute{
                        Name: "name",
                        Expr: &expression{
                            src: &stringVal{
                                Value: "Ermintrude",
                                SrcRange: hcl.Range{
                                    Filename: "test.json",
                                    Start: hcl.Pos{
                                        Byte:   8,
                                        Line:   1,
                                        Column: 9,
                                    },
                                    End: hcl.Pos{
                                        Byte:   20,
                                        Line:   1,
                                        Column: 21,
                                    },
                                },
                            },
                        },
                        Range: hcl.Range{
                            Filename: "test.json",
                            Start: hcl.Pos{
                                Byte:   1,
                                Line:   1,
                                Column: 2,
                            },
                            End: hcl.Pos{
                                Byte:   20,
                                Line:   1,
                                Column: 21,
                            },
                        },
                        NameRange: hcl.Range{
                            Filename: "test.json",
                            Start: hcl.Pos{
                                Byte:   1,
                                Line:   1,
                                Column: 2,
                            },
                            End: hcl.Pos{
                                Byte:   7,
                                Line:   1,
                                Column: 8,
                            },
                        },
                    },
                },
                MissingItemRange: hcl.Range{
                    Filename: "test.json",
                    Start:    hcl.Pos{Line: 1, Column: 21, Byte: 20},
                    End:      hcl.Pos{Line: 1, Column: 22, Byte: 21},
                },
            },
            0,
        },
        {
            `[{"name":"Ermintrude"}]`,
            &hcl.BodySchema{
                Attributes: []hcl.AttributeSchema{
                    {
                        Name: "name",
                    },
                },
            },
            &hcl.BodyContent{
                Attributes: map[string]*hcl.Attribute{
                    "name": &hcl.Attribute{
                        Name: "name",
                        Expr: &expression{
                            src: &stringVal{
                                Value: "Ermintrude",
                                SrcRange: hcl.Range{
                                    Filename: "test.json",
                                    Start: hcl.Pos{
                                        Byte:   9,
                                        Line:   1,
                                        Column: 10,
                                    },
                                    End: hcl.Pos{
                                        Byte:   21,
                                        Line:   1,
                                        Column: 22,
                                    },
                                },
                            },
                        },
                        Range: hcl.Range{
                            Filename: "test.json",
                            Start: hcl.Pos{
                                Byte:   2,
                                Line:   1,
                                Column: 3,
                            },
                            End: hcl.Pos{
                                Byte:   21,
                                Line:   1,
                                Column: 22,
                            },
                        },
                        NameRange: hcl.Range{
                            Filename: "test.json",
                            Start: hcl.Pos{
                                Byte:   2,
                                Line:   1,
                                Column: 3,
                            },
                            End: hcl.Pos{
                                Byte:   8,
                                Line:   1,
                                Column: 9,
                            },
                        },
                    },
                },
                MissingItemRange: hcl.Range{
                    Filename: "test.json",
                    Start:    hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:      hcl.Pos{Line: 1, Column: 2, Byte: 1},
                },
            },
            0,
        },
        {
            `{"name":"Ermintrude"}`,
            &hcl.BodySchema{
                Attributes: []hcl.AttributeSchema{
                    {
                        Name:     "name",
                        Required: true,
                    },
                    {
                        Name:     "age",
                        Required: true,
                    },
                },
            },
            &hcl.BodyContent{
                Attributes: map[string]*hcl.Attribute{
                    "name": &hcl.Attribute{
                        Name: "name",
                        Expr: &expression{
                            src: &stringVal{
                                Value: "Ermintrude",
                                SrcRange: hcl.Range{
                                    Filename: "test.json",
                                    Start: hcl.Pos{
                                        Byte:   8,
                                        Line:   1,
                                        Column: 9,
                                    },
                                    End: hcl.Pos{
                                        Byte:   20,
                                        Line:   1,
                                        Column: 21,
                                    },
                                },
                            },
                        },
                        Range: hcl.Range{
                            Filename: "test.json",
                            Start: hcl.Pos{
                                Byte:   1,
                                Line:   1,
                                Column: 2,
                            },
                            End: hcl.Pos{
                                Byte:   20,
                                Line:   1,
                                Column: 21,
                            },
                        },
                        NameRange: hcl.Range{
                            Filename: "test.json",
                            Start: hcl.Pos{
                                Byte:   1,
                                Line:   1,
                                Column: 2,
                            },
                            End: hcl.Pos{
                                Byte:   7,
                                Line:   1,
                                Column: 8,
                            },
                        },
                    },
                },
                MissingItemRange: hcl.Range{
                    Filename: "test.json",
                    Start:    hcl.Pos{Line: 1, Column: 21, Byte: 20},
                    End:      hcl.Pos{Line: 1, Column: 22, Byte: 21},
                },
            },
            1,
        },
        {
            `{"resource": null}`,
            &hcl.BodySchema{
                Blocks: []hcl.BlockHeaderSchema{
                    {
                        Type: "resource",
                    },
                },
            },
            &hcl.BodyContent{
                Attributes: map[string]*hcl.Attribute{},
                // We don't find any blocks if the value is json null.
                Blocks: nil,
                MissingItemRange: hcl.Range{
                    Filename: "test.json",
                    Start:    hcl.Pos{Line: 1, Column: 18, Byte: 17},
                    End:      hcl.Pos{Line: 1, Column: 19, Byte: 18},
                },
            },
            0,
        },
        {
            `{"resource": { "nested": null }}`,
            &hcl.BodySchema{
                Blocks: []hcl.BlockHeaderSchema{
                    {
                        Type:       "resource",
                        LabelNames: []string{"name"},
                    },
                },
            },
            &hcl.BodyContent{
                Attributes: map[string]*hcl.Attribute{},
                Blocks:     nil,
                MissingItemRange: hcl.Range{
                    Filename: "test.json",
                    Start:    hcl.Pos{Line: 1, Column: 32, Byte: 31},
                    End:      hcl.Pos{Line: 1, Column: 33, Byte: 32},
                },
            },
            0,
        },
        {
            `{"resource":{}}`,
            &hcl.BodySchema{
                Blocks: []hcl.BlockHeaderSchema{
                    {
                        Type: "resource",
                    },
                },
            },
            &hcl.BodyContent{
                Attributes: map[string]*hcl.Attribute{},
                Blocks: hcl.Blocks{
                    {
                        Type:   "resource",
                        Labels: []string{},
                        Body: &body{
                            val: &objectVal{
                                Attrs: []*objectAttr{},
                                SrcRange: hcl.Range{
                                    Filename: "test.json",
                                    Start: hcl.Pos{
                                        Byte:   12,
                                        Line:   1,
                                        Column: 13,
                                    },
                                    End: hcl.Pos{
                                        Byte:   14,
                                        Line:   1,
                                        Column: 15,
                                    },
                                },
                                OpenRange: hcl.Range{
                                    Filename: "test.json",
                                    Start: hcl.Pos{
                                        Byte:   12,
                                        Line:   1,
                                        Column: 13,
                                    },
                                    End: hcl.Pos{
                                        Byte:   13,
                                        Line:   1,
                                        Column: 14,
                                    },
                                },
                                CloseRange: hcl.Range{
                                    Filename: "test.json",
                                    Start: hcl.Pos{
                                        Byte:   13,
                                        Line:   1,
                                        Column: 14,
                                    },
                                    End: hcl.Pos{
                                        Byte:   14,
                                        Line:   1,
                                        Column: 15,
                                    },
                                },
                            },
                        },

                        DefRange: hcl.Range{
                            Filename: "test.json",
                            Start: hcl.Pos{
                                Byte:   12,
                                Line:   1,
                                Column: 13,
                            },
                            End: hcl.Pos{
                                Byte:   13,
                                Line:   1,
                                Column: 14,
                            },
                        },
                        TypeRange: hcl.Range{
                            Filename: "test.json",
                            Start: hcl.Pos{
                                Byte:   1,
                                Line:   1,
                                Column: 2,
                            },
                            End: hcl.Pos{
                                Byte:   11,
                                Line:   1,
                                Column: 12,
                            },
                        },
                        LabelRanges: []hcl.Range{},
                    },
                },
                MissingItemRange: hcl.Range{
                    Filename: "test.json",
                    Start:    hcl.Pos{Line: 1, Column: 15, Byte: 14},
                    End:      hcl.Pos{Line: 1, Column: 16, Byte: 15},
                },
            },
            0,
        },
        {
            `{"resource":[{},{}]}`,
            &hcl.BodySchema{
                Blocks: []hcl.BlockHeaderSchema{
                    {
                        Type: "resource",
                    },
                },
            },
            &hcl.BodyContent{
                Attributes: map[string]*hcl.Attribute{},
                Blocks: hcl.Blocks{
                    {
                        Type:   "resource",
                        Labels: []string{},
                        Body: &body{
                            val: &objectVal{
                                Attrs: []*objectAttr{},
                                SrcRange: hcl.Range{
                                    Filename: "test.json",
                                    Start: hcl.Pos{
                                        Byte:   13,
                                        Line:   1,
                                        Column: 14,
                                    },
                                    End: hcl.Pos{
                                        Byte:   15,
                                        Line:   1,
                                        Column: 16,
                                    },
                                },
                                OpenRange: hcl.Range{
                                    Filename: "test.json",
                                    Start: hcl.Pos{
                                        Byte:   13,
                                        Line:   1,
                                        Column: 14,
                                    },
                                    End: hcl.Pos{
                                        Byte:   14,
                                        Line:   1,
                                        Column: 15,
                                    },
                                },
                                CloseRange: hcl.Range{
                                    Filename: "test.json",
                                    Start: hcl.Pos{
                                        Byte:   14,
                                        Line:   1,
                                        Column: 15,
                                    },
                                    End: hcl.Pos{
                                        Byte:   15,
                                        Line:   1,
                                        Column: 16,
                                    },
                                },
                            },
                        },

                        DefRange: hcl.Range{
                            Filename: "test.json",
                            Start: hcl.Pos{
                                Byte:   12,
                                Line:   1,
                                Column: 13,
                            },
                            End: hcl.Pos{
                                Byte:   13,
                                Line:   1,
                                Column: 14,
                            },
                        },
                        TypeRange: hcl.Range{
                            Filename: "test.json",
                            Start: hcl.Pos{
                                Byte:   1,
                                Line:   1,
                                Column: 2,
                            },
                            End: hcl.Pos{
                                Byte:   11,
                                Line:   1,
                                Column: 12,
                            },
                        },
                        LabelRanges: []hcl.Range{},
                    },
                    {
                        Type:   "resource",
                        Labels: []string{},
                        Body: &body{
                            val: &objectVal{
                                Attrs: []*objectAttr{},
                                SrcRange: hcl.Range{
                                    Filename: "test.json",
                                    Start: hcl.Pos{
                                        Byte:   16,
                                        Line:   1,
                                        Column: 17,
                                    },
                                    End: hcl.Pos{
                                        Byte:   18,
                                        Line:   1,
                                        Column: 19,
                                    },
                                },
                                OpenRange: hcl.Range{
                                    Filename: "test.json",
                                    Start: hcl.Pos{
                                        Byte:   16,
                                        Line:   1,
                                        Column: 17,
                                    },
                                    End: hcl.Pos{
                                        Byte:   17,
                                        Line:   1,
                                        Column: 18,
                                    },
                                },
                                CloseRange: hcl.Range{
                                    Filename: "test.json",
                                    Start: hcl.Pos{
                                        Byte:   17,
                                        Line:   1,
                                        Column: 18,
                                    },
                                    End: hcl.Pos{
                                        Byte:   18,
                                        Line:   1,
                                        Column: 19,
                                    },
                                },
                            },
                        },

                        DefRange: hcl.Range{
                            Filename: "test.json",
                            Start: hcl.Pos{
                                Byte:   12,
                                Line:   1,
                                Column: 13,
                            },
                            End: hcl.Pos{
                                Byte:   13,
                                Line:   1,
                                Column: 14,
                            },
                        },
                        TypeRange: hcl.Range{
                            Filename: "test.json",
                            Start: hcl.Pos{
                                Byte:   1,
                                Line:   1,
                                Column: 2,
                            },
                            End: hcl.Pos{
                                Byte:   11,
                                Line:   1,
                                Column: 12,
                            },
                        },
                        LabelRanges: []hcl.Range{},
                    },
                },
                MissingItemRange: hcl.Range{
                    Filename: "test.json",
                    Start:    hcl.Pos{Line: 1, Column: 20, Byte: 19},
                    End:      hcl.Pos{Line: 1, Column: 21, Byte: 20},
                },
            },
            0,
        },
        {
            `{"resource":{"foo_instance":{"bar":{}}}}`,
            &hcl.BodySchema{
                Blocks: []hcl.BlockHeaderSchema{
                    {
                        Type:       "resource",
                        LabelNames: []string{"type", "name"},
                    },
                },
            },
            &hcl.BodyContent{
                Attributes: map[string]*hcl.Attribute{},
                Blocks: hcl.Blocks{
                    {
                        Type:   "resource",
                        Labels: []string{"foo_instance", "bar"},
                        Body: &body{
                            val: &objectVal{
                                Attrs: []*objectAttr{},
                                SrcRange: hcl.Range{
                                    Filename: "test.json",
                                    Start: hcl.Pos{
                                        Byte:   35,
                                        Line:   1,
                                        Column: 36,
                                    },
                                    End: hcl.Pos{
                                        Byte:   37,
                                        Line:   1,
                                        Column: 38,
                                    },
                                },
                                OpenRange: hcl.Range{
                                    Filename: "test.json",
                                    Start: hcl.Pos{
                                        Byte:   35,
                                        Line:   1,
                                        Column: 36,
                                    },
                                    End: hcl.Pos{
                                        Byte:   36,
                                        Line:   1,
                                        Column: 37,
                                    },
                                },
                                CloseRange: hcl.Range{
                                    Filename: "test.json",
                                    Start: hcl.Pos{
                                        Byte:   36,
                                        Line:   1,
                                        Column: 37,
                                    },
                                    End: hcl.Pos{
                                        Byte:   37,
                                        Line:   1,
                                        Column: 38,
                                    },
                                },
                            },
                        },

                        DefRange: hcl.Range{
                            Filename: "test.json",
                            Start: hcl.Pos{
                                Byte:   35,
                                Line:   1,
                                Column: 36,
                            },
                            End: hcl.Pos{
                                Byte:   36,
                                Line:   1,
                                Column: 37,
                            },
                        },
                        TypeRange: hcl.Range{
                            Filename: "test.json",
                            Start: hcl.Pos{
                                Byte:   1,
                                Line:   1,
                                Column: 2,
                            },
                            End: hcl.Pos{
                                Byte:   11,
                                Line:   1,
                                Column: 12,
                            },
                        },
                        LabelRanges: []hcl.Range{
                            {
                                Filename: "test.json",
                                Start: hcl.Pos{
                                    Byte:   13,
                                    Line:   1,
                                    Column: 14,
                                },
                                End: hcl.Pos{
                                    Byte:   27,
                                    Line:   1,
                                    Column: 28,
                                },
                            },
                            {
                                Filename: "test.json",
                                Start: hcl.Pos{
                                    Byte:   29,
                                    Line:   1,
                                    Column: 30,
                                },
                                End: hcl.Pos{
                                    Byte:   34,
                                    Line:   1,
                                    Column: 35,
                                },
                            },
                        },
                    },
                },
                MissingItemRange: hcl.Range{
                    Filename: "test.json",
                    Start:    hcl.Pos{Line: 1, Column: 40, Byte: 39},
                    End:      hcl.Pos{Line: 1, Column: 41, Byte: 40},
                },
            },
            0,
        },
        {
            `{"resource":{"foo_instance":[{"bar":{}}, {"bar":{}}]}}`,
            &hcl.BodySchema{
                Blocks: []hcl.BlockHeaderSchema{
                    {
                        Type:       "resource",
                        LabelNames: []string{"type", "name"},
                    },
                },
            },
            &hcl.BodyContent{
                Attributes: map[string]*hcl.Attribute{},
                Blocks: hcl.Blocks{
                    {
                        Type:   "resource",
                        Labels: []string{"foo_instance", "bar"},
                        Body: &body{
                            val: &objectVal{
                                Attrs: []*objectAttr{},
                                SrcRange: hcl.Range{
                                    Filename: "test.json",
                                    Start: hcl.Pos{
                                        Byte:   36,
                                        Line:   1,
                                        Column: 37,
                                    },
                                    End: hcl.Pos{
                                        Byte:   38,
                                        Line:   1,
                                        Column: 39,
                                    },
                                },
                                OpenRange: hcl.Range{
                                    Filename: "test.json",
                                    Start: hcl.Pos{
                                        Byte:   36,
                                        Line:   1,
                                        Column: 37,
                                    },
                                    End: hcl.Pos{
                                        Byte:   37,
                                        Line:   1,
                                        Column: 38,
                                    },
                                },
                                CloseRange: hcl.Range{
                                    Filename: "test.json",
                                    Start: hcl.Pos{
                                        Byte:   37,
                                        Line:   1,
                                        Column: 38,
                                    },
                                    End: hcl.Pos{
                                        Byte:   38,
                                        Line:   1,
                                        Column: 39,
                                    },
                                },
                            },
                        },

                        DefRange: hcl.Range{
                            Filename: "test.json",
                            Start: hcl.Pos{
                                Byte:   36,
                                Line:   1,
                                Column: 37,
                            },
                            End: hcl.Pos{
                                Byte:   37,
                                Line:   1,
                                Column: 38,
                            },
                        },
                        TypeRange: hcl.Range{
                            Filename: "test.json",
                            Start: hcl.Pos{
                                Byte:   1,
                                Line:   1,
                                Column: 2,
                            },
                            End: hcl.Pos{
                                Byte:   11,
                                Line:   1,
                                Column: 12,
                            },
                        },
                        LabelRanges: []hcl.Range{
                            {
                                Filename: "test.json",
                                Start: hcl.Pos{
                                    Byte:   13,
                                    Line:   1,
                                    Column: 14,
                                },
                                End: hcl.Pos{
                                    Byte:   27,
                                    Line:   1,
                                    Column: 28,
                                },
                            },
                            {
                                Filename: "test.json",
                                Start: hcl.Pos{
                                    Byte:   30,
                                    Line:   1,
                                    Column: 31,
                                },
                                End: hcl.Pos{
                                    Byte:   35,
                                    Line:   1,
                                    Column: 36,
                                },
                            },
                        },
                    },
                    {
                        Type:   "resource",
                        Labels: []string{"foo_instance", "bar"},
                        Body: &body{
                            val: &objectVal{
                                Attrs: []*objectAttr{},
                                SrcRange: hcl.Range{
                                    Filename: "test.json",
                                    Start: hcl.Pos{
                                        Byte:   36,
                                        Line:   1,
                                        Column: 37,
                                    },
                                    End: hcl.Pos{
                                        Byte:   38,
                                        Line:   1,
                                        Column: 39,
                                    },
                                },
                                OpenRange: hcl.Range{
                                    Filename: "test.json",
                                    Start: hcl.Pos{
                                        Byte:   36,
                                        Line:   1,
                                        Column: 37,
                                    },
                                    End: hcl.Pos{
                                        Byte:   37,
                                        Line:   1,
                                        Column: 38,
                                    },
                                },
                                CloseRange: hcl.Range{
                                    Filename: "test.json",
                                    Start: hcl.Pos{
                                        Byte:   37,
                                        Line:   1,
                                        Column: 38,
                                    },
                                    End: hcl.Pos{
                                        Byte:   38,
                                        Line:   1,
                                        Column: 39,
                                    },
                                },
                            },
                        },

                        DefRange: hcl.Range{
                            Filename: "test.json",
                            Start: hcl.Pos{
                                Byte:   48,
                                Line:   1,
                                Column: 49,
                            },
                            End: hcl.Pos{
                                Byte:   49,
                                Line:   1,
                                Column: 50,
                            },
                        },
                        TypeRange: hcl.Range{
                            Filename: "test.json",
                            Start: hcl.Pos{
                                Byte:   1,
                                Line:   1,
                                Column: 2,
                            },
                            End: hcl.Pos{
                                Byte:   11,
                                Line:   1,
                                Column: 12,
                            },
                        },
                        LabelRanges: []hcl.Range{
                            {
                                Filename: "test.json",
                                Start: hcl.Pos{
                                    Byte:   13,
                                    Line:   1,
                                    Column: 14,
                                },
                                End: hcl.Pos{
                                    Byte:   27,
                                    Line:   1,
                                    Column: 28,
                                },
                            },
                            {
                                Filename: "test.json",
                                Start: hcl.Pos{
                                    Byte:   42,
                                    Line:   1,
                                    Column: 43,
                                },
                                End: hcl.Pos{
                                    Byte:   47,
                                    Line:   1,
                                    Column: 48,
                                },
                            },
                        },
                    },
                },
                MissingItemRange: hcl.Range{
                    Filename: "test.json",
                    Start:    hcl.Pos{Line: 1, Column: 54, Byte: 53},
                    End:      hcl.Pos{Line: 1, Column: 55, Byte: 54},
                },
            },
            0,
        },
        {
            `{"name":"Ermintrude"}`,
            &hcl.BodySchema{
                Blocks: []hcl.BlockHeaderSchema{
                    {
                        Type: "name",
                    },
                },
            },
            &hcl.BodyContent{
                Attributes: map[string]*hcl.Attribute{},
                MissingItemRange: hcl.Range{
                    Filename: "test.json",
                    Start:    hcl.Pos{Line: 1, Column: 21, Byte: 20},
                    End:      hcl.Pos{Line: 1, Column: 22, Byte: 21},
                },
            },
            1, // name is supposed to be a block
        },
        {
            `[{"name":"Ermintrude"},{"name":"Ermintrude"}]`,
            &hcl.BodySchema{
                Attributes: []hcl.AttributeSchema{
                    {
                        Name: "name",
                    },
                },
            },
            &hcl.BodyContent{
                Attributes: map[string]*hcl.Attribute{
                    "name": {
                        Name: "name",
                        Expr: &expression{
                            src: &stringVal{
                                Value: "Ermintrude",
                                SrcRange: hcl.Range{
                                    Filename: "test.json",
                                    Start: hcl.Pos{
                                        Byte:   8,
                                        Line:   1,
                                        Column: 9,
                                    },
                                    End: hcl.Pos{
                                        Byte:   20,
                                        Line:   1,
                                        Column: 21,
                                    },
                                },
                            },
                        },
                        Range: hcl.Range{
                            Filename: "test.json",
                            Start: hcl.Pos{
                                Byte:   2,
                                Line:   1,
                                Column: 3,
                            },
                            End: hcl.Pos{
                                Byte:   21,
                                Line:   1,
                                Column: 22,
                            },
                        },
                        NameRange: hcl.Range{
                            Filename: "test.json",
                            Start: hcl.Pos{
                                Byte:   2,
                                Line:   1,
                                Column: 3,
                            },
                            End: hcl.Pos{
                                Byte:   8,
                                Line:   1,
                                Column: 9,
                            },
                        },
                    },
                },
                MissingItemRange: hcl.Range{
                    Filename: "test.json",
                    Start:    hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:      hcl.Pos{Line: 1, Column: 2, Byte: 1},
                },
            },
            1, // "name" attribute is defined twice
        },
    }

    for i, test := range tests {
        t.Run(fmt.Sprintf("%02d-%s", i, test.src), func(t *testing.T) {
            file, diags := Parse([]byte(test.src), "test.json")
            if len(diags) != 0 {
                t.Fatalf("Parse produced diagnostics: %s", diags)
            }
            got, _, diags := file.Body.PartialContent(test.schema)
            if len(diags) != test.diagCount {
                t.Errorf("Wrong number of diagnostics %d; want %d", len(diags), test.diagCount)
                for _, diag := range diags {
                    t.Logf(" - %s", diag)
                }
            }

            for _, problem := range deep.Equal(got, test.want) {
                t.Error(problem)
            }
        })
    }
}

func TestBodyContent(t *testing.T) {
    // We test most of the functionality already in TestBodyPartialContent, so
    // this test focuses on the handling of extraneous attributes.
    tests := []struct {
        src       string
        schema    *hcl.BodySchema
        diagCount int
    }{
        {
            `{"unknown": true}`,
            &hcl.BodySchema{},
            1,
        },
        {
            `{"//": "comment that should be ignored"}`,
            &hcl.BodySchema{},
            0,
        },
        {
            `{"unknow": true}`,
            &hcl.BodySchema{
                Attributes: []hcl.AttributeSchema{
                    {
                        Name: "unknown",
                    },
                },
            },
            1,
        },
        {
            `{"unknow": true, "unnown": true}`,
            &hcl.BodySchema{
                Attributes: []hcl.AttributeSchema{
                    {
                        Name: "unknown",
                    },
                },
            },
            2,
        },
    }

    for i, test := range tests {
        t.Run(fmt.Sprintf("%02d-%s", i, test.src), func(t *testing.T) {
            file, diags := Parse([]byte(test.src), "test.json")
            if len(diags) != 0 {
                t.Fatalf("Parse produced diagnostics: %s", diags)
            }
            _, diags = file.Body.Content(test.schema)
            if len(diags) != test.diagCount {
                t.Errorf("Wrong number of diagnostics %d; want %d", len(diags), test.diagCount)
                for _, diag := range diags {
                    t.Logf(" - %s", diag)
                }
            }
        })
    }
}

func TestJustAttributes(t *testing.T) {
    // We test most of the functionality already in TestBodyPartialContent, so
    // this test focuses on the handling of extraneous attributes.
    tests := []struct {
        src       string
        want      hcl.Attributes
        diagCount int
    }{
        {
            `{}`,
            map[string]*hcl.Attribute{},
            0,
        },
        {
            `{"foo": true}`,
            map[string]*hcl.Attribute{
                "foo": {
                    Name: "foo",
                    Expr: &expression{
                        src: &booleanVal{
                            Value: true,
                            SrcRange: hcl.Range{
                                Filename: "test.json",
                                Start:    hcl.Pos{Byte: 8, Line: 1, Column: 9},
                                End:      hcl.Pos{Byte: 12, Line: 1, Column: 13},
                            },
                        },
                    },
                    Range: hcl.Range{
                        Filename: "test.json",
                        Start:    hcl.Pos{Byte: 1, Line: 1, Column: 2},
                        End:      hcl.Pos{Byte: 12, Line: 1, Column: 13},
                    },
                    NameRange: hcl.Range{
                        Filename: "test.json",
                        Start:    hcl.Pos{Byte: 1, Line: 1, Column: 2},
                        End:      hcl.Pos{Byte: 6, Line: 1, Column: 7},
                    },
                },
            },
            0,
        },
        {
            `{"//": "comment that should be ignored"}`,
            map[string]*hcl.Attribute{},
            0,
        },
        {
            `{"foo": true, "foo": true}`,
            map[string]*hcl.Attribute{
                "foo": {
                    Name: "foo",
                    Expr: &expression{
                        src: &booleanVal{
                            Value: true,
                            SrcRange: hcl.Range{
                                Filename: "test.json",
                                Start:    hcl.Pos{Byte: 8, Line: 1, Column: 9},
                                End:      hcl.Pos{Byte: 12, Line: 1, Column: 13},
                            },
                        },
                    },
                    Range: hcl.Range{
                        Filename: "test.json",
                        Start:    hcl.Pos{Byte: 1, Line: 1, Column: 2},
                        End:      hcl.Pos{Byte: 12, Line: 1, Column: 13},
                    },
                    NameRange: hcl.Range{
                        Filename: "test.json",
                        Start:    hcl.Pos{Byte: 1, Line: 1, Column: 2},
                        End:      hcl.Pos{Byte: 6, Line: 1, Column: 7},
                    },
                },
            },
            1, // attribute foo was already defined
        },
    }

    for i, test := range tests {
        t.Run(fmt.Sprintf("%02d-%s", i, test.src), func(t *testing.T) {
            file, diags := Parse([]byte(test.src), "test.json")
            if len(diags) != 0 {
                t.Fatalf("Parse produced diagnostics: %s", diags)
            }
            got, diags := file.Body.JustAttributes()
            if len(diags) != test.diagCount {
                t.Errorf("Wrong number of diagnostics %d; want %d", len(diags), test.diagCount)
                for _, diag := range diags {
                    t.Logf(" - %s", diag)
                }
            }
            if !reflect.DeepEqual(got, test.want) {
                t.Errorf("wrong result\ngot:  %s\nwant: %s", spew.Sdump(got), spew.Sdump(test.want))
            }
        })
    }
}

func TestExpressionVariables(t *testing.T) {
    tests := []struct {
        Src  string
        Want []hcl.Traversal
    }{
        {
            `{"a":true}`,
            nil,
        },
        {
            `{"a":"${foo}"}`,
            []hcl.Traversal{
                {
                    hcl.TraverseRoot{
                        Name: "foo",
                        SrcRange: hcl.Range{
                            Filename: "test.json",
                            Start:    hcl.Pos{Line: 1, Column: 9, Byte: 8},
                            End:      hcl.Pos{Line: 1, Column: 12, Byte: 11},
                        },
                    },
                },
            },
        },
        {
            `{"a":["${foo}"]}`,
            []hcl.Traversal{
                {
                    hcl.TraverseRoot{
                        Name: "foo",
                        SrcRange: hcl.Range{
                            Filename: "test.json",
                            Start:    hcl.Pos{Line: 1, Column: 10, Byte: 9},
                            End:      hcl.Pos{Line: 1, Column: 13, Byte: 12},
                        },
                    },
                },
            },
        },
        {
            `{"a":{"b":"${foo}"}}`,
            []hcl.Traversal{
                {
                    hcl.TraverseRoot{
                        Name: "foo",
                        SrcRange: hcl.Range{
                            Filename: "test.json",
                            Start:    hcl.Pos{Line: 1, Column: 14, Byte: 13},
                            End:      hcl.Pos{Line: 1, Column: 17, Byte: 16},
                        },
                    },
                },
            },
        },
        {
            `{"a":{"${foo}":"b"}}`,
            []hcl.Traversal{
                {
                    hcl.TraverseRoot{
                        Name: "foo",
                        SrcRange: hcl.Range{
                            Filename: "test.json",
                            Start:    hcl.Pos{Line: 1, Column: 10, Byte: 9},
                            End:      hcl.Pos{Line: 1, Column: 13, Byte: 12},
                        },
                    },
                },
            },
        },
    }

    for _, test := range tests {
        t.Run(test.Src, func(t *testing.T) {
            file, diags := Parse([]byte(test.Src), "test.json")
            if len(diags) != 0 {
                t.Fatalf("Parse produced diagnostics: %s", diags)
            }
            attrs, diags := file.Body.JustAttributes()
            if len(diags) != 0 {
                t.Fatalf("JustAttributes produced diagnostics: %s", diags)
            }
            got := attrs["a"].Expr.Variables()
            if !reflect.DeepEqual(got, test.Want) {
                t.Errorf("wrong result\ngot:  %s\nwant: %s", spew.Sdump(got), spew.Sdump(test.Want))
            }
        })
    }
}

func TestExpressionAsTraversal(t *testing.T) {
    e := &expression{
        src: &stringVal{
            Value: "foo.bar[0]",
        },
    }
    traversal := e.AsTraversal()
    if len(traversal) != 3 {
        t.Fatalf("incorrect traversal %#v; want length 3", traversal)
    }
}

func TestStaticExpressionList(t *testing.T) {
    e := &expression{
        src: &arrayVal{
            Values: []node{
                &stringVal{
                    Value: "hello",
                },
            },
        },
    }
    exprs := e.ExprList()
    if len(exprs) != 1 {
        t.Fatalf("incorrect exprs %#v; want length 1", exprs)
    }
    if exprs[0].(*expression).src != e.src.(*arrayVal).Values[0] {
        t.Fatalf("wrong first expression node")
    }
}

func TestExpression_Value(t *testing.T) {
    src := `{
  "string": "string_val",
  "number": 5,
  "bool_true": true,
  "bool_false": false,
  "array": ["a"],
  "object": {"key": "value"},
  "null": null
}`
    expected := map[string]cty.Value{
        "string":     cty.StringVal("string_val"),
        "number":     cty.NumberIntVal(5),
        "bool_true":  cty.BoolVal(true),
        "bool_false": cty.BoolVal(false),
        "array":      cty.TupleVal([]cty.Value{cty.StringVal("a")}),
        "object": cty.ObjectVal(map[string]cty.Value{
            "key": cty.StringVal("value"),
        }),
        "null": cty.NullVal(cty.DynamicPseudoType),
    }

    file, diags := Parse([]byte(src), "")
    if len(diags) != 0 {
        t.Errorf("got %d diagnostics on parse; want 0", len(diags))
        for _, diag := range diags {
            t.Logf("- %s", diag.Error())
        }
    }
    if file == nil {
        t.Errorf("got nil File; want actual file")
    }
    if file.Body == nil {
        t.Fatalf("got nil Body; want actual body")
    }
    attrs, diags := file.Body.JustAttributes()
    if len(diags) != 0 {
        t.Errorf("got %d diagnostics on decode; want 0", len(diags))
        for _, diag := range diags {
            t.Logf("- %s", diag.Error())
        }
    }

    for ek, ev := range expected {
        val, diags := attrs[ek].Expr.Value(&hcl.EvalContext{})
        if len(diags) != 0 {
            t.Errorf("got %d diagnostics on eval; want 0", len(diags))
            for _, diag := range diags {
                t.Logf("- %s", diag.Error())
            }
        }

        if !val.RawEquals(ev) {
            t.Errorf("wrong result %#v; want %#v", val, ev)
        }
    }

}

// TestExpressionValue_Diags asserts that Value() returns diagnostics
// from nested evaluations for complex objects (e.g. ObjectVal, ArrayVal)
func TestExpressionValue_Diags(t *testing.T) {
    cases := []struct {
        name     string
        src      string
        expected cty.Value
        error    string
    }{
        {
            name:     "string: happy",
            src:      `{"v": "happy ${VAR1}"}`,
            expected: cty.StringVal("happy case"),
        },
        {
            name:     "string: unhappy",
            src:      `{"v": "happy ${UNKNOWN}"}`,
            expected: cty.UnknownVal(cty.String),
            error:    "Unknown variable",
        },
        {
            name: "object_val: happy",
            src:  `{"v": {"key": "happy ${VAR1}"}}`,
            expected: cty.ObjectVal(map[string]cty.Value{
                "key": cty.StringVal("happy case"),
            }),
        },
        {
            name: "object_val: unhappy",
            src:  `{"v": {"key": "happy ${UNKNOWN}"}}`,
            expected: cty.ObjectVal(map[string]cty.Value{
                "key": cty.UnknownVal(cty.String),
            }),
            error: "Unknown variable",
        },
        {
            name: "object_key: happy",
            src:  `{"v": {"happy ${VAR1}": "val"}}`,
            expected: cty.ObjectVal(map[string]cty.Value{
                "happy case": cty.StringVal("val"),
            }),
        },
        {
            name:     "object_key: unhappy",
            src:      `{"v": {"happy ${UNKNOWN}": "val"}}`,
            expected: cty.DynamicVal,
            error:    "Unknown variable",
        },
        {
            name:     "array: happy",
            src:      `{"v": ["happy ${VAR1}"]}`,
            expected: cty.TupleVal([]cty.Value{cty.StringVal("happy case")}),
        },
        {
            name:     "array: unhappy",
            src:      `{"v": ["happy ${UNKNOWN}"]}`,
            expected: cty.TupleVal([]cty.Value{cty.UnknownVal(cty.String)}),
            error:    "Unknown variable",
        },
    }

    ctx := &hcl.EvalContext{
        Variables: map[string]cty.Value{
            "VAR1": cty.StringVal("case"),
        },
    }

    for _, c := range cases {
        t.Run(c.name, func(t *testing.T) {
            file, diags := Parse([]byte(c.src), "")

            if len(diags) != 0 {
                t.Errorf("got %d diagnostics on parse; want 0", len(diags))
                for _, diag := range diags {
                    t.Logf("- %s", diag.Error())
                }
                t.FailNow()
            }
            if file == nil {
                t.Errorf("got nil File; want actual file")
            }
            if file.Body == nil {
                t.Fatalf("got nil Body; want actual body")
            }

            attrs, diags := file.Body.JustAttributes()
            if len(diags) != 0 {
                t.Errorf("got %d diagnostics on decode; want 0", len(diags))
                for _, diag := range diags {
                    t.Logf("- %s", diag.Error())
                }
                t.FailNow()
            }

            val, diags := attrs["v"].Expr.Value(ctx)
            if c.error == "" && len(diags) != 0 {
                t.Errorf("got %d diagnostics on eval; want 0", len(diags))
                for _, diag := range diags {
                    t.Logf("- %s", diag.Error())
                }
                t.FailNow()
            } else if c.error != "" && len(diags) == 0 {
                t.Fatalf("got 0 diagnostics on eval, want 1 with %s", c.error)
            } else if c.error != "" && len(diags) != 0 {
                if !strings.Contains(diags[0].Error(), c.error) {
                    t.Fatalf("found error: %s; want %s", diags[0].Error(), c.error)
                }
            }

            if !val.RawEquals(c.expected) {
                t.Errorf("wrong result %#v; want %#v", val, c.expected)
            }
        })
    }

}

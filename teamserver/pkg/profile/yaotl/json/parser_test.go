package json

import (
    "math/big"
    "testing"

    "github.com/go-test/deep"
    "Havoc/pkg/profile/yaotl"
)

func init() {
    deep.MaxDepth = 999
}

func TestParse(t *testing.T) {
    tests := []struct {
        Input     string
        Want      node
        DiagCount int
    }{
        // Simple, single-token constructs
        {
            `true`,
            &booleanVal{
                Value: true,
                SrcRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:   hcl.Pos{Line: 1, Column: 5, Byte: 4},
                },
            },
            0,
        },
        {
            `false`,
            &booleanVal{
                Value: false,
                SrcRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:   hcl.Pos{Line: 1, Column: 6, Byte: 5},
                },
            },
            0,
        },
        {
            `null`,
            &nullVal{
                SrcRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:   hcl.Pos{Line: 1, Column: 5, Byte: 4},
                },
            },
            0,
        },
        {
            `undefined`,
            invalidVal{hcl.Range{
                Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                End:   hcl.Pos{Line: 1, Column: 10, Byte: 9},
            }},
            1,
        },
        {
            `flase`,
            invalidVal{hcl.Range{
                Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                End:   hcl.Pos{Line: 1, Column: 6, Byte: 5},
            }},
            1,
        },
        {
            `"hello"`,
            &stringVal{
                Value: "hello",
                SrcRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:   hcl.Pos{Line: 1, Column: 8, Byte: 7},
                },
            },
            0,
        },
        {
            `"hello\nworld"`,
            &stringVal{
                Value: "hello\nworld",
                SrcRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:   hcl.Pos{Line: 1, Column: 15, Byte: 14},
                },
            },
            0,
        },
        {
            `"hello \"world\""`,
            &stringVal{
                Value: `hello "world"`,
                SrcRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:   hcl.Pos{Line: 1, Column: 18, Byte: 17},
                },
            },
            0,
        },
        {
            `"hello \\"`,
            &stringVal{
                Value: "hello \\",
                SrcRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:   hcl.Pos{Line: 1, Column: 11, Byte: 10},
                },
            },
            0,
        },
        {
            `"hello`,
            invalidVal{hcl.Range{
                Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                End:   hcl.Pos{Line: 1, Column: 7, Byte: 6},
            }},
            1,
        },
        {
            `"he\llo"`,
            invalidVal{hcl.Range{
                Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                End:   hcl.Pos{Line: 1, Column: 9, Byte: 8},
            }},
            1,
        },
        {
            `1`,
            &numberVal{
                Value: mustBigFloat("1"),
                SrcRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:   hcl.Pos{Line: 1, Column: 2, Byte: 1},
                },
            },
            0,
        },
        {
            `1.2`,
            &numberVal{
                Value: mustBigFloat("1.2"),
                SrcRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:   hcl.Pos{Line: 1, Column: 4, Byte: 3},
                },
            },
            0,
        },
        {
            `-1`,
            &numberVal{
                Value: mustBigFloat("-1"),
                SrcRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:   hcl.Pos{Line: 1, Column: 3, Byte: 2},
                },
            },
            0,
        },
        {
            `1.2e5`,
            &numberVal{
                Value: mustBigFloat("120000"),
                SrcRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:   hcl.Pos{Line: 1, Column: 6, Byte: 5},
                },
            },
            0,
        },
        {
            `1.2e+5`,
            &numberVal{
                Value: mustBigFloat("120000"),
                SrcRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:   hcl.Pos{Line: 1, Column: 7, Byte: 6},
                },
            },
            0,
        },
        {
            `1.2e-5`,
            &numberVal{
                Value: mustBigFloat("1.2e-5"),
                SrcRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:   hcl.Pos{Line: 1, Column: 7, Byte: 6},
                },
            },
            0,
        },
        {
            `.1`,
            invalidVal{hcl.Range{
                Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                End:   hcl.Pos{Line: 1, Column: 3, Byte: 2},
            }},
            1,
        },
        {
            `+2`,
            invalidVal{hcl.Range{
                Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                End:   hcl.Pos{Line: 1, Column: 3, Byte: 2},
            }},
            1,
        },
        {
            `1 2`,
            &numberVal{
                Value: mustBigFloat("1"),
                SrcRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:   hcl.Pos{Line: 1, Column: 2, Byte: 1},
                },
            },
            1,
        },

        // Objects
        {
            `{"hello": true}`,
            &objectVal{
                Attrs: []*objectAttr{
                    {
                        Name: "hello",
                        Value: &booleanVal{
                            Value: true,
                            SrcRange: hcl.Range{
                                Start: hcl.Pos{Line: 1, Column: 11, Byte: 10},
                                End:   hcl.Pos{Line: 1, Column: 15, Byte: 14},
                            },
                        },
                        NameRange: hcl.Range{
                            Start: hcl.Pos{Line: 1, Column: 2, Byte: 1},
                            End:   hcl.Pos{Line: 1, Column: 9, Byte: 8},
                        },
                    },
                },
                SrcRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:   hcl.Pos{Line: 1, Column: 16, Byte: 15},
                },
                OpenRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:   hcl.Pos{Line: 1, Column: 2, Byte: 1},
                },
                CloseRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 15, Byte: 14},
                    End:   hcl.Pos{Line: 1, Column: 16, Byte: 15},
                },
            },
            0,
        },
        {
            `{"hello": true, "bye": false}`,
            &objectVal{
                Attrs: []*objectAttr{
                    {
                        Name: "hello",
                        Value: &booleanVal{
                            Value: true,
                            SrcRange: hcl.Range{
                                Start: hcl.Pos{Line: 1, Column: 11, Byte: 10},
                                End:   hcl.Pos{Line: 1, Column: 15, Byte: 14},
                            },
                        },
                        NameRange: hcl.Range{
                            Start: hcl.Pos{Line: 1, Column: 2, Byte: 1},
                            End:   hcl.Pos{Line: 1, Column: 9, Byte: 8},
                        },
                    },
                    {
                        Name: "bye",
                        Value: &booleanVal{
                            Value: false,
                            SrcRange: hcl.Range{
                                Start: hcl.Pos{Line: 1, Column: 24, Byte: 23},
                                End:   hcl.Pos{Line: 1, Column: 29, Byte: 28},
                            },
                        },
                        NameRange: hcl.Range{
                            Start: hcl.Pos{Line: 1, Column: 17, Byte: 16},
                            End:   hcl.Pos{Line: 1, Column: 22, Byte: 21},
                        },
                    },
                },
                SrcRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:   hcl.Pos{Line: 1, Column: 30, Byte: 29},
                },
                OpenRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:   hcl.Pos{Line: 1, Column: 2, Byte: 1},
                },
                CloseRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 29, Byte: 28},
                    End:   hcl.Pos{Line: 1, Column: 30, Byte: 29},
                },
            },
            0,
        },
        {
            `{}`,
            &objectVal{
                Attrs: []*objectAttr{},
                SrcRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:   hcl.Pos{Line: 1, Column: 3, Byte: 2},
                },
                OpenRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:   hcl.Pos{Line: 1, Column: 2, Byte: 1},
                },
                CloseRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 2, Byte: 1},
                    End:   hcl.Pos{Line: 1, Column: 3, Byte: 2},
                },
            },
            0,
        },
        {
            `{"hello":true`,
            invalidVal{hcl.Range{
                Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                End:   hcl.Pos{Line: 1, Column: 2, Byte: 1},
            }},
            1,
        },
        {
            `{"hello":true]`,
            invalidVal{hcl.Range{
                Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                End:   hcl.Pos{Line: 1, Column: 2, Byte: 1},
            }},
            1,
        },
        {
            `{"hello":true,}`,
            invalidVal{hcl.Range{
                Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                End:   hcl.Pos{Line: 1, Column: 2, Byte: 1},
            }},
            1,
        },
        {
            `{true:false}`,
            invalidVal{hcl.Range{
                Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                End:   hcl.Pos{Line: 1, Column: 2, Byte: 1},
            }},
            1,
        },
        {
            `{"hello": true, "hello": true}`,
            &objectVal{
                Attrs: []*objectAttr{
                    {
                        Name: "hello",
                        Value: &booleanVal{
                            Value: true,
                            SrcRange: hcl.Range{
                                Start: hcl.Pos{Line: 1, Column: 11, Byte: 10},
                                End:   hcl.Pos{Line: 1, Column: 15, Byte: 14},
                            },
                        },
                        NameRange: hcl.Range{
                            Start: hcl.Pos{Line: 1, Column: 2, Byte: 1},
                            End:   hcl.Pos{Line: 1, Column: 9, Byte: 8},
                        },
                    },
                    {
                        Name: "hello",
                        Value: &booleanVal{
                            Value: true,
                            SrcRange: hcl.Range{
                                Start: hcl.Pos{Line: 1, Column: 26, Byte: 25},
                                End:   hcl.Pos{Line: 1, Column: 30, Byte: 29},
                            },
                        },
                        NameRange: hcl.Range{
                            Start: hcl.Pos{Line: 1, Column: 17, Byte: 16},
                            End:   hcl.Pos{Line: 1, Column: 24, Byte: 23},
                        },
                    },
                },
                SrcRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:   hcl.Pos{Line: 1, Column: 31, Byte: 30},
                },
                OpenRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:   hcl.Pos{Line: 1, Column: 2, Byte: 1},
                },
                CloseRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 30, Byte: 29},
                    End:   hcl.Pos{Line: 1, Column: 31, Byte: 30},
                },
            },
            0,
        },
        {
            `{"hello": true, "hello": true, "hello", true}`,
            invalidVal{hcl.Range{
                Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                End:   hcl.Pos{Line: 1, Column: 2, Byte: 1},
            }},
            1, // comma used where colon is expected
        },
        {
            `{"hello", "world"}`,
            invalidVal{hcl.Range{
                Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                End:   hcl.Pos{Line: 1, Column: 2, Byte: 1},
            }},
            1,
        },
        {
            `[]`,
            &arrayVal{
                Values: []node{},
                SrcRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:   hcl.Pos{Line: 1, Column: 3, Byte: 2},
                },
                OpenRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:   hcl.Pos{Line: 1, Column: 2, Byte: 1},
                },
            },
            0,
        },
        {
            `[true]`,
            &arrayVal{
                Values: []node{
                    &booleanVal{
                        Value: true,
                        SrcRange: hcl.Range{
                            Start: hcl.Pos{Line: 1, Column: 2, Byte: 1},
                            End:   hcl.Pos{Line: 1, Column: 6, Byte: 5},
                        },
                    },
                },
                SrcRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:   hcl.Pos{Line: 1, Column: 7, Byte: 6},
                },
                OpenRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:   hcl.Pos{Line: 1, Column: 2, Byte: 1},
                },
            },
            0,
        },
        {
            `[true, false]`,
            &arrayVal{
                Values: []node{
                    &booleanVal{
                        Value: true,
                        SrcRange: hcl.Range{
                            Start: hcl.Pos{Line: 1, Column: 2, Byte: 1},
                            End:   hcl.Pos{Line: 1, Column: 6, Byte: 5},
                        },
                    },
                    &booleanVal{
                        Value: false,
                        SrcRange: hcl.Range{
                            Start: hcl.Pos{Line: 1, Column: 8, Byte: 7},
                            End:   hcl.Pos{Line: 1, Column: 13, Byte: 12},
                        },
                    },
                },
                SrcRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:   hcl.Pos{Line: 1, Column: 14, Byte: 13},
                },
                OpenRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:   hcl.Pos{Line: 1, Column: 2, Byte: 1},
                },
            },
            0,
        },
        {
            `[[]]`,
            &arrayVal{
                Values: []node{
                    &arrayVal{
                        Values: []node{},
                        SrcRange: hcl.Range{
                            Start: hcl.Pos{Line: 1, Column: 2, Byte: 1},
                            End:   hcl.Pos{Line: 1, Column: 4, Byte: 3},
                        },
                        OpenRange: hcl.Range{
                            Start: hcl.Pos{Line: 1, Column: 2, Byte: 1},
                            End:   hcl.Pos{Line: 1, Column: 3, Byte: 2},
                        },
                    },
                },
                SrcRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:   hcl.Pos{Line: 1, Column: 5, Byte: 4},
                },
                OpenRange: hcl.Range{
                    Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                    End:   hcl.Pos{Line: 1, Column: 2, Byte: 1},
                },
            },
            0,
        },
        {
            `[`,
            invalidVal{hcl.Range{
                Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                End:   hcl.Pos{Line: 1, Column: 2, Byte: 1},
            }},
            2,
        },
        {
            `[true`,
            invalidVal{hcl.Range{
                Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                End:   hcl.Pos{Line: 1, Column: 2, Byte: 1},
            }},
            1,
        },
        {
            `]`,
            invalidVal{hcl.Range{
                Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                End:   hcl.Pos{Line: 1, Column: 2, Byte: 1},
            }},
            1,
        },
        {
            `[true,]`,
            invalidVal{hcl.Range{
                Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                End:   hcl.Pos{Line: 1, Column: 2, Byte: 1},
            }},
            1,
        },
        {
            `[[],]`,
            invalidVal{hcl.Range{
                Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                End:   hcl.Pos{Line: 1, Column: 2, Byte: 1},
            }},
            1,
        },
        {
            `["hello":true]`,
            invalidVal{hcl.Range{
                Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                End:   hcl.Pos{Line: 1, Column: 2, Byte: 1},
            }},
            1,
        },
        {
            `[true}`,
            invalidVal{hcl.Range{
                Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                End:   hcl.Pos{Line: 1, Column: 2, Byte: 1},
            }},
            1,
        },
        {
            `{"wrong"=true}`,
            invalidVal{hcl.Range{
                Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                End:   hcl.Pos{Line: 1, Column: 2, Byte: 1},
            }},
            1,
        },
        {
            `{"wrong" = true}`,
            invalidVal{hcl.Range{
                Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                End:   hcl.Pos{Line: 1, Column: 2, Byte: 1},
            }},
            1,
        },
        {
            `{"wrong" true}`,
            invalidVal{hcl.Range{
                Start: hcl.Pos{Line: 1, Column: 1, Byte: 0},
                End:   hcl.Pos{Line: 1, Column: 2, Byte: 1},
            }},
            1,
        },
    }

    for _, test := range tests {
        t.Run(test.Input, func(t *testing.T) {
            got, diag := parseFileContent([]byte(test.Input), "", hcl.Pos{Byte: 0, Line: 1, Column: 1})

            if len(diag) != test.DiagCount {
                t.Errorf("got %d diagnostics; want %d", len(diag), test.DiagCount)
                for _, d := range diag {
                    t.Logf("  - %s", d.Error())
                }
            }

            if diff := deep.Equal(got, test.Want); diff != nil {
                for _, problem := range diff {
                    t.Error(problem)
                }
            }
        })
    }
}

func TestParseWithPos(t *testing.T) {
    tests := []struct {
        Input     string
        StartPos  hcl.Pos
        Want      node
        DiagCount int
    }{
        // Simple, single-token constructs
        {
            `true`,
            hcl.Pos{Byte: 0, Line: 3, Column: 10},
            &booleanVal{
                Value: true,
                SrcRange: hcl.Range{
                    Start: hcl.Pos{Line: 3, Column: 10, Byte: 0},
                    End:   hcl.Pos{Line: 3, Column: 14, Byte: 4},
                },
            },
            0,
        },
    }

    for _, test := range tests {
        t.Run(test.Input, func(t *testing.T) {
            got, diag := parseFileContent([]byte(test.Input), "", test.StartPos)

            if len(diag) != test.DiagCount {
                t.Errorf("got %d diagnostics; want %d", len(diag), test.DiagCount)
                for _, d := range diag {
                    t.Logf("  - %s", d.Error())
                }
            }

            if diff := deep.Equal(got, test.Want); diff != nil {
                for _, problem := range diff {
                    t.Error(problem)
                }
            }
        })
    }
}

func mustBigFloat(s string) *big.Float {
    f, _, err := (&big.Float{}).Parse(s, 10)
    if err != nil {
        panic(err)
    }
    return f
}

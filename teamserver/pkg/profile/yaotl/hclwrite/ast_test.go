package hclwrite

import (
	"fmt"
	"strings"
)

type TestTreeNode struct {
	Type string
	Val  string

	Children []TestTreeNode
}

func makeTestTree(n *node) (root TestTreeNode) {
	const us = "hclwrite."
	const usPtr = "*hclwrite."
	root.Type = fmt.Sprintf("%T", n.content)
	if strings.HasPrefix(root.Type, us) {
		root.Type = root.Type[len(us):]
	} else if strings.HasPrefix(root.Type, usPtr) {
		root.Type = root.Type[len(usPtr):]
	}

	type WithVal interface {
		testValue() string
	}
	hasTestVal := false
	if withVal, ok := n.content.(WithVal); ok {
		root.Val = withVal.testValue()
		hasTestVal = true
	}

	n.content.walkChildNodes(func(n *node) {
		root.Children = append(root.Children, makeTestTree(n))
	})

	// If we didn't end up with any children then this is probably a leaf
	// node, so we'll set its content value to it raw bytes if we didn't
	// already set a test value.
	if !hasTestVal && len(root.Children) == 0 {
		toks := n.content.BuildTokens(nil)
		root.Val = toks.testValue()
	}

	return root
}

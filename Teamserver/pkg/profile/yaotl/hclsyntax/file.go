package hclsyntax

import (
	"github.com/Cracked5pider/Havoc/teamserver/pkg/profile/yaotl"
)

// File is the top-level object resulting from parsing a configuration file.
type File struct {
	Body  *Body
	Bytes []byte
}

func (f *File) AsHCLFile() *hcl.File {
	return &hcl.File{
		Body:  f.Body,
		Bytes: f.Bytes,

		// TODO: The Nav object, once we have an implementation of it
	}
}

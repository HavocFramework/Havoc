package events

import (
	"time"

	"Havoc/pkg/packager"
)

var Teamserver teamserver

func (teamserver) Logger(text string) packager.Package {
	var Package packager.Package

	Package.Head.Event = packager.Type.Teamserver.Type
	// Time Day Month Year
	Package.Head.Time = time.Now().Format("02/01/2006 15:04:05")

	Package.Body.Info = make(map[string]interface{})
	Package.Body.SubEvent = packager.Type.Teamserver.Log
	Package.Body.Info["Text"] = text

	return Package
}

func (teamserver) Profile(profile string) packager.Package {
	var Package packager.Package

	Package.Head.Event = packager.Type.Teamserver.Type
	// Time Day Month Year
	Package.Head.Time = time.Now().Format("02/01/2006 15:04:05")

	Package.Body.Info = make(map[string]interface{})
	Package.Body.SubEvent = packager.Type.Teamserver.Log
	Package.Body.Info["profile"] = profile

	return Package
}

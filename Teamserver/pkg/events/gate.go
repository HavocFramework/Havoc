package events

import (
    "encoding/base64"
    "time"

    "Havoc/pkg/packager"
)

var Gate gate

func (g gate) SendStageless(Format string, payload []byte) packager.Package {
    var Package packager.Package

    Package.Head.Event = packager.Type.Gate.Type
    Package.Head.Time = time.Now().Format("02/01/2006 15:04:05")
    Package.Head.OneTime = "true"

    Package.Body.Info = make(map[string]interface{})
    Package.Body.SubEvent = packager.Type.Gate.Stageless

    Package.Body.Info["PayloadArray"] = base64.StdEncoding.EncodeToString(payload)
    Package.Body.Info["Format"] = Format
    Package.Body.Info["FileName"] = Format

    return Package
}

func (g gate) SendConsoleMessage(MsgType, text string) packager.Package {
    var Package packager.Package

    Package.Head.Event = packager.Type.Gate.Type
    Package.Head.Time = time.Now().Format("02/01/2006 15:04:05")
    Package.Head.OneTime = "true"

    Package.Body.Info = make(map[string]interface{})
    Package.Body.SubEvent = packager.Type.Gate.Stageless

    Package.Body.Info["MessageType"] = MsgType
    Package.Body.Info["Message"] = text

    return Package
}

package events

import (
    "time"

    "Havoc/pkg/packager"
)

var ChatLog chatLog

func (chatLog) NewUserConnected(User string) packager.Package {
    var Package packager.Package

    Package.Head.Event = packager.Type.Chat.Type
    Package.Head.Time = time.Now().Format("02/01/2006 15:04:05")

    Package.Body.Info = make(map[string]interface{})
    Package.Body.SubEvent = packager.Type.Chat.NewUser
    Package.Body.Info["User"] = User

    return Package
}

func (chatLog) UserDisconnected(User string) packager.Package {
    var Package packager.Package

    Package.Head.Event = packager.Type.Chat.Type
    // Time Day Month Year
    Package.Head.Time = time.Now().Format("02/01/2006 15:04:05")

    Package.Body.Info = make(map[string]interface{})
    Package.Body.SubEvent = packager.Type.Chat.UserDisconnected
    Package.Body.Info["User"] = User

    return Package
}

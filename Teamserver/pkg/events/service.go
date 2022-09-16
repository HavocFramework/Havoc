package events

import (
    "time"

    "Havoc/pkg/packager"
)

var Service service

func (service) AgentRegister(AgentData string) packager.Package {
    var Package packager.Package

    Package.Head.Event = packager.Type.Service.Type
    Package.Head.Time = time.Now().Format("02/01/2006 15:04:05")

    Package.Body.SubEvent = packager.Type.InitConnection.Success
    Package.Body.Info = map[string]interface{}{
        "Agent": AgentData,
    }

    return Package
}

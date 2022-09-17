package events

import (
	"strconv"
	"strings"
	"time"

	"Havoc/pkg/handlers"
	"Havoc/pkg/packager"
)

var Listener listeners

func (listeners) ListenerAdd(FromUser string, Type int, Config any) packager.Package {
    var Package packager.Package

    Package.Head.Event = packager.Type.Listener.Type
    Package.Head.Time = time.Now().Format("02/01/2006 15:04:05")
    Package.Head.User = FromUser
    Package.Body.SubEvent = packager.Type.Listener.Add

    switch Type {

    case handlers.LISTENER_HTTP:

        Package.Body.Info = make(map[string]interface{})
        Package.Body.Info["Name"] = Config.(*handlers.HTTP).Config.Name
        Package.Body.Info["Host"] = Config.(*handlers.HTTP).Config.Hosts
        Package.Body.Info["Port"] = Config.(*handlers.HTTP).Config.Port
        Package.Body.Info["Protocol"] = handlers.DEMON_HTTP
        Package.Body.Info["Secure"] = "false"

        if Config.(*handlers.HTTP).Config.Secure {
            Package.Body.Info["Secure"] = "true"
        }

        Package.Body.Info["Connected"] = strconv.Itoa(Config.(*handlers.HTTP).Demons)

        if Config.(*handlers.HTTP).Active {
            Package.Body.Info["Status"] = "Online"
        } else {
            Package.Body.Info["Status"] = "Offline"
        }

        break

    case handlers.LISTENER_EXTERNAL:

        Package.Body.Info = make(map[string]interface{})
        Package.Body.Info["Name"] = Config.(*handlers.External).Config.Name
        Package.Body.Info["Host"] = Config.(*handlers.External).Config.Endpoint
        Package.Body.Info["Port"] = ""
        Package.Body.Info["Protocol"] = handlers.DEMON_EXTERNAL
        Package.Body.Info["Status"] = "Online"

        break

    case handlers.LISTENER_PIVOT_SMB:

        Package.Body.Info = make(map[string]interface{})
        Package.Body.Info["Name"] = Config.(*handlers.SMB).Config.Name
        Package.Body.Info["Host"] = Config.(*handlers.SMB).Config.PipeName
        Package.Body.Info["Port"] = ""
        Package.Body.Info["Protocol"] = handlers.DEMON_PIVOT_SMB
        Package.Body.Info["Status"] = "Online"

        break

    }

    return Package
}

func (listeners) ListenerError(FromUser string, ListenerName string, err error) packager.Package {
    var (
        Package     packager.Package
        listenerErr = strings.Split(err.Error(), ":")
    )
    Package.Head.Event = packager.Type.Listener.Type
    Package.Head.Time = time.Now().Format("02/01/2006 15:04:05")
    Package.Head.User = FromUser

    Package.Body.SubEvent = packager.Type.Listener.Error

    Package.Body.Info = make(map[string]interface{})
    Package.Body.Info["Error"] = listenerErr[len(listenerErr)-1]
    Package.Body.Info["Name"] = ListenerName

    return Package
}

func (listeners) ListenerMark(ListenerName string, Mark string) packager.Package {
    var Package packager.Package

    Package.Head.Event = packager.Type.Listener.Type
    Package.Head.Time = time.Now().Format("02/01/2006 15:04:05")

    Package.Body.SubEvent = packager.Type.Listener.Mark

    Package.Body.Info = make(map[string]interface{})
    Package.Body.Info["Name"] = ListenerName
    Package.Body.Info["Mark"] = Mark

    return Package
}

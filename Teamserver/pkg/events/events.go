package events

import (
    "encoding/json"
    "net"
    "time"

    "Havoc/pkg/packager"
    "Havoc/pkg/profile"
)

type (
    chatLog    int
    listeners  int
    demons     int
    gate       int
    service    int
    teamserver int
)

type EventInterface interface {
    EventAppend(pk packager.Package) []packager.Package
    EventBroadcast(FromUser string, pk packager.Package)
    SendEvent(id string, pk packager.Package) error
}

func Authenticated(authed bool) packager.Package {
    var Package packager.Package

    Package.Head.Event = packager.Type.InitConnection.Type
    Package.Head.Time = time.Now().Format("02/01/2006 15:04:05")

    Package.Body.Info = make(map[string]interface{})
    if authed {
        Package.Body.SubEvent = packager.Type.InitConnection.Success
        Package.Body.Info["Message"] = "Successful Authenticated"
    } else {
        Package.Body.SubEvent = packager.Type.InitConnection.Error
        Package.Body.Info["Message"] = "Wrong Password"
    }

    return Package
}

func UserAlreadyExits() packager.Package {
    var Package packager.Package

    Package.Head.Event = packager.Type.InitConnection.Type
    Package.Head.Time = time.Now().Format("02/01/2006 15:04:05")

    Package.Body.Info = make(map[string]interface{})
    Package.Body.SubEvent = packager.Type.InitConnection.Error
    Package.Body.Info["Message"] = "User already exits"

    return Package
}

func UserDoNotExists() packager.Package {
    var Package packager.Package

    Package.Head.Event = packager.Type.InitConnection.Type
    Package.Head.Time = time.Now().Format("02/01/2006 15:04:05")

    Package.Body.Info = make(map[string]interface{})
    Package.Body.SubEvent = packager.Type.InitConnection.Error
    Package.Body.Info["Message"] = "User doesn't exits"

    return Package
}

func SendProfile(profile *profile.Profile) packager.Package {
    var (
        Package   packager.Package
        JsonBytes []byte
        Addresses string
    )

    Package.Head.Event = packager.Type.InitConnection.Type
    Package.Head.Time = time.Now().Format("02/01/2006 15:04:05")

    Package.Body.SubEvent = packager.Type.InitConnection.Profile
    Package.Body.Info = make(map[string]interface{})

    JsonBytes, err := json.Marshal(*profile.Config.Demon)
    if err != nil {
        return packager.Package{}
    }
    Package.Body.Info["Demon"] = string(JsonBytes)

    addrs, err := net.InterfaceAddrs()
    if err != nil {
        return packager.Package{}
    }
    for _, address := range addrs {
        if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
            if ipnet.IP.To4() != nil {
                if len(Addresses) == 0 {
                    Addresses = ipnet.IP.String()
                } else {
                    Addresses += ", " + ipnet.IP.String()
                }
            }
        }
    }

    Package.Body.Info["TeamserverIPs"] = Addresses

    return Package
}

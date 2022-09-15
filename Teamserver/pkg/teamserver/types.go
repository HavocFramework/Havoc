package teamserver

import (
    "Havoc/pkg/demons"
    "Havoc/pkg/packager"
    "Havoc/pkg/profile"
    "Havoc/pkg/service"
    "github.com/gin-gonic/gin"
    "github.com/gorilla/websocket"
)

type Listener struct {
    Name   string
    Type   int
    Config any
}

type Client struct {
    ClientID      string
    Username      string
    GlobalIP      string
    ClientVersion string
    Connection    *websocket.Conn
    Packager      *packager.Packager
    Authenticated bool
    SessionID     string
}

type Users struct {
    Name     string
    Password string
    Hashed   bool
    Online   bool
}

type serverFlags struct {
    Host string
    Port string

    Profile  string
    Verbose  bool
    Debug    bool
    DebugDev bool
}

type utilFlags struct {
    NoBanner bool
    Debug    bool
    Verbose  bool

    Test bool

    ListOperators bool
}

type TeamserverFlags struct {
    Server serverFlags
    Util   utilFlags
}

type Teamserver struct {
    Flags       TeamserverFlags
    Profile     *profile.Profile
    Clients     map[string]*Client
    Fingerprint string
    Users       []Users
    EventsList  []packager.Package
    Service     *service.Service

    Server struct {
        Path   string
        Engine *gin.Engine
    }

    Agents    demons.Agents
    Listeners []*Listener

    Settings struct {
        Compiler64 string
        Compiler32 string
        Nasm       string
    }
}

package handlers

import (
    "Havoc/pkg/demons"
)
import "github.com/gin-gonic/gin"

type Listener interface {
    Start()
    SetConfig(Config any)
    Stop()
}

type (
    HTTPConfig struct {
        Name      string
        Hosts     string
        Port      string
        UserAgent string
        Headers   []string
        Uris      []string
        Secure    bool

        Proxy struct {
            Enabled  bool
            Type     string
            Host     string
            Port     string
            Username string
            Password string
        }

        Response struct {
            Headers []string
        }
    }

    ExternalConfig struct {
        Name     string
        Endpoint string
    }

    SMBConfig struct {
        Name     string
        PipeName string
    }
)

type (
    HTTP struct {
        Config HTTPConfig

        GinEngine *gin.Engine

        TLS struct {
            Cert []byte
            Key  []byte

            CertPath string
            KeyPath  string
        }

        RoutineFunc demons.RoutineFunc

        Active bool
        Demons int
    }

    SMB struct {
        Config SMBConfig

        RoutineFunc demons.RoutineFunc
        ParentChild []struct {
            Parent any
            Child  any
        }
    }

    External struct {
        Config ExternalConfig

        // teamserver websocket engine
        engine      *gin.Engine
        RoutineFunc demons.RoutineFunc
    }
)

const (
    LISTENER_HTTP      = 1
    LISTENER_PIVOT_SMB = 2
    LISTENER_EXTERNAL  = 3

    DEMON_HTTPS     = "Https"
    DEMON_HTTP      = "Http"
    DEMON_EXTERNAL  = "External"
    DEMON_PIVOT_SMB = "Smb"
)

package handlers

import (
    "Havoc/pkg/agent"
    "net/http"
)
import "github.com/gin-gonic/gin"

type (
    HTTPConfig struct {
        Name         string
        Hosts        []string
        HostBind     string
        HostRotation string
        Port         string
        UserAgent    string
        Headers      []string
        Uris         []string
        HostHeader   string
        Secure       bool
        CertPath     string
        KeyPath      string

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
        Server    *http.Server

        TLS struct {
            Cert []byte
            Key  []byte

            CertPath string
            KeyPath  string
        }

        RoutineFunc agent.RoutineFunc

        Active bool
    }

    SMB struct {
        Config SMBConfig

        RoutineFunc agent.RoutineFunc
        ParentChild []struct {
            Parent any
            Child  any
        }
    }

    External struct {
        Config ExternalConfig

        // teamserver websocket engine
        engine      *gin.Engine
        RoutineFunc agent.RoutineFunc
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

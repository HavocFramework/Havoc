package handlers

import (
    "io"
    "net/http"
    "strings"

    "Havoc/pkg/colors"
    "Havoc/pkg/logger"
    "encoding/hex"

    "github.com/gin-gonic/gin"
)

func NewExternal(WebSocketEngine any, Config ExternalConfig) *External {
    var external = new(External)

    external.engine = WebSocketEngine.(*gin.Engine)
    external.Config = Config

    return external
}

func (e *External) Start() {
    logger.Info("Started \"" + colors.Green(e.Config.Name) + "\" listener: " + colors.BlueUnderline("external://"+e.Config.Endpoint))

    pk := e.Teamserver.ListenerAdd("", LISTENER_EXTERNAL, e)
    e.Teamserver.EventAppend(pk)
    e.Teamserver.EventBroadcast("", pk)
}

// Request
// The way the external c2 handles or parses the request is like the HTTP listener.
// Only one agent package can be parsed (at least for the demon agent).
// for 3rd party agents you have more power over the packages since
// the teamserver won't parse them.
func (e *External) Request(ctx *gin.Context) {
    logger.Debug("ExternalC2 [" + e.Config.Name + "] client connected")

    Body, err := io.ReadAll(ctx.Request.Body)
    if err != nil {
        logger.Debug("Error while reading request: " + err.Error())
    }

    logger.Debug(" - Exc2 Host : " + ctx.Request.Host)
    logger.Debug(" - Exc2 Body : \n" + hex.Dump(Body))

    ExternalIP := strings.Split(ctx.Request.RemoteAddr, ":")[0]

    if Response, Success := parseAgentRequest(e.Teamserver, Body, ExternalIP); Success {
        _, err := ctx.Writer.Write(Response.Bytes())
        if err != nil {
            logger.Debug("Failed to write to request: " + err.Error())
            ctx.Status(http.StatusNotFound)
            return
        }
    } else {
        ctx.AbortWithStatus(http.StatusNotFound)
        return
    }

    ctx.AbortWithStatus(http.StatusOK)
    return
}

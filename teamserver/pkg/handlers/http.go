package handlers

import (
	"context"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"Havoc/pkg/colors"
	"Havoc/pkg/common/certs"
	"Havoc/pkg/logger"
	"Havoc/pkg/logr"

	"github.com/gin-gonic/gin"
)

func NewConfigHttp() *HTTP {
	var config = new(HTTP)

	config.GinEngine = gin.New()

	return config
}

func (h *HTTP) generateCertFiles() bool {

	var (
		err          error
		ListenerName string
		ListenerPath string
	)

	reg, err := regexp.Compile("[^a-zA-Z0-9]+")
	if err != nil {
		log.Fatal(err)
	}

	ListenerName = reg.ReplaceAllString(h.Config.Name, "")
	ListenerPath = logr.LogrInstance.ListenerPath + "/" + ListenerName + "/"

	logger.Debug("Listener Path:", ListenerPath)

	if _, err := os.Stat(ListenerPath); os.IsNotExist(err) {
		if err = os.Mkdir(ListenerPath, os.ModePerm); err != nil {
			logger.Error("Failed to create Logr listener " + h.Config.Name + " folder: " + err.Error())
			return false
		}
	}

	h.TLS.CertPath = ListenerPath + "server.crt"
	h.TLS.KeyPath = ListenerPath + "server.key"

	h.TLS.Cert, h.TLS.Key, err = certs.HTTPSGenerateRSACertificate(h.Config.HostBind)

	err = os.WriteFile(h.TLS.CertPath, h.TLS.Cert, 0644)
	if err != nil {
		logger.Error("Couldn't save server cert file: " + err.Error())
		return false
	}

	err = os.WriteFile(h.TLS.KeyPath, h.TLS.Key, 0644)
	if err != nil {
		logger.Error("Couldn't save server key file: " + err.Error())
		return false
	}

	logger.Debug("Successful generated tls certifications")

	return true
}

func (h *HTTP) request(ctx *gin.Context) {
	Body, err := io.ReadAll(ctx.Request.Body)
	if err != nil {
		logger.Debug("Error while reading request: " + err.Error())
	}

	logger.Debug(" - HTTP Host : " + ctx.Request.Host)
	logger.Debug(" - HTTP Body : \n" + hex.Dump(Body))

	for _, Header := range h.Config.Response.Headers {
		var hdr = strings.Split(Header, ":")
		if len(hdr) > 1 {
			ctx.Header(hdr[0], hdr[1])
		}
	}

	if Response, Success := parseAgentRequest(h.Teamserver, Body); Success {
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

func (h *HTTP) Start() {
	logger.Debug("Setup HTTP/s Server")

	if len(h.Config.Hosts) == 0 && h.Config.Port == "" && h.Config.Name == "" {
		logger.Error("HTTP Hosts/Port/Name not set")
		return
	}

	h.GinEngine.POST("/*endpoint", h.request)
	h.Active = true

	if h.Config.Secure {
		// TODO: only generate certs if h.Config.Cert is emtpy
		if h.generateCertFiles() {
			logger.Info("Started \"" + colors.Green(h.Config.Name) + "\" listener: " + colors.BlueUnderline("https://"+h.Config.HostBind+":"+h.Config.Port))

			pk := h.Teamserver.ListenerAdd("", LISTENER_HTTP, h)
			h.Teamserver.EventAppend(pk)
			h.Teamserver.EventBroadcast("", pk)

			go func() {
				var (
					CertPath = h.TLS.CertPath
					KeyPath  = h.TLS.KeyPath
				)

				h.Server = &http.Server{
					Addr:    h.Config.HostBind + ":" + h.Config.Port,
					Handler: h.GinEngine,
				}

				if h.Config.Cert.Cert != "" && h.Config.Cert.Key != "" {
					CertPath = h.Config.Cert.Cert
					KeyPath = h.Config.Cert.Key
				}

				err := h.Server.ListenAndServeTLS(CertPath, KeyPath)
				if err != nil {
					logger.Error("Couldn't start HTTPs handler: " + err.Error())
					h.Active = false
					h.Teamserver.EventListenerError(h.Config.Name, err)
				}
			}()
		} else {
			logger.Error("Failed to generate server tls certifications")
		}
	} else {
		logger.Info("Started \"" + colors.Green(h.Config.Name) + "\" listener: " + colors.BlueUnderline("http://"+h.Config.HostBind+":"+h.Config.Port))

		pk := h.Teamserver.ListenerAdd("", LISTENER_HTTP, h)
		h.Teamserver.EventAppend(pk)
		h.Teamserver.EventBroadcast("", pk)

		go func() {
			h.Server = &http.Server{
				Addr:    h.Config.HostBind + ":" + h.Config.Port,
				Handler: h.GinEngine,
			}

			err := h.Server.ListenAndServe()
			if err != nil {
				logger.Error("Couldn't start HTTP handler: " + err.Error())
				h.Active = false
				h.Teamserver.EventListenerError(h.Config.Name, err)
			}
		}()
	}
}

func (h *HTTP) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.Server.Shutdown(ctx); err != nil {
		return err
	}
	// catching ctx.Done(). timeout of 5 seconds.
	select {
	case <-ctx.Done():
		logger.Debug("timeout of 5 seconds.")
	}

	return nil
}

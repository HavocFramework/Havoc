package service

import (
    "encoding/base64"
    "encoding/json"
    "fmt"

    "Havoc/pkg/agent"
    "Havoc/pkg/logger"
    "Havoc/pkg/utils"
)

type CommandParam struct {
    Name       string `json:"Name"`
    IsFilePath bool   `json:"IsFilePath"`
    IsOptional bool   `json:"IsOptional"`
}

type Command struct {
    Name        string         `json:"Name"`
    Description string         `json:"Description"`
    Help        string         `json:"Help"`
    NeedAdmin   bool           `json:"NeedAdmin"`
    Mitr        []string       `json:"Mitr"`
    Params      []CommandParam `json:"Params"`
}

type AgentService struct {
    Name       string `json:"Name"`
    MagicValue string `json:"MagicValue"`
    Author     string `json:"Author"`
    Formats    []struct {
        Name      string
        Extension string
    } `json:"Formats"`
    SupportedOS    []string               `json:"SupportedOS"`
    Description    string                 `json:"Description"`
    Commands       []Command              `json:"Commands"`
    BuildingConfig map[string]interface{} `json:"BuildingConfig"`

    client  *ClientService `json:"-"`
    service *Service       `json:"-"`
}

func NewAgentService(data []byte, client *ClientService) *AgentService {
    var service = new(AgentService)

    service.client = client
    err := json.Unmarshal(data, service)
    if err != nil {
        logger.Error("Failed to unmarshal json to object: " + err.Error())
        return nil
    }

    return service
}

func (a *AgentService) Json() string {
    var JsonString, err = json.Marshal(a)
    if err != nil {
        return ""
    }

    return string(JsonString)
}

func (a *AgentService) SendTask(Command map[string]interface{}, AgentInfo any) {

    var AgentRequest = map[string]map[string]interface{}{
        "Head": {
            "Type": HeadAgent,
        },
        "Body": {
            "Type":    BodyAgentTask,
            "Agent":   AgentInfo,
            "Command": Command,
            "Task":    "Add",
        },
    }

    if err := a.client.WriteJson(AgentRequest); err != nil {
        logger.Error("Failed to write json to websocket: " + err.Error())
        return
    }
}

func (a *AgentService) SendResponse(AgentInfo any, Header agent.Header) []byte {

    var (
        randID = utils.GenerateID(6)

        header = map[string]any{
            "Size":       fmt.Sprintf("%v", Header.Size),
            "AgentID":    fmt.Sprintf("%08x", Header.AgentID),
            "MagicValue": fmt.Sprintf("%x", Header.MagicValue),
        }

        AgentResponse = map[string]map[string]interface{}{
            "Head": {
                "Type": HeadAgent,
            },
            "Body": {
                "Type":        BodyAgentResponse,
                "Agent":       AgentInfo,
                "RandID":      randID,
                "AgentHeader": header,
                "Response":    base64.StdEncoding.EncodeToString(Header.Data.Buffer()),
            },
        }
    )

    logger.Debug(AgentResponse)

    if a.client.Responses == nil {
        a.client.Responses = make(map[string]chan []byte)
    }

    a.client.Responses[randID] = make(chan []byte)

    a.client.Mutex.Lock()
    err := a.client.Conn.WriteJSON(AgentResponse)
    a.client.Mutex.Unlock()

    if err != nil {
        logger.Error("Failed to write json to websocket: " + err.Error())
        return nil
    }

    var data []byte
    if channel, ok := a.client.Responses[randID]; ok {
        data = <-channel

        close(a.client.Responses[randID])
        delete(a.client.Responses, randID)
    }

    return data
}

func (a *AgentService) SendAgentBuildRequest(ClientID string, Config map[string]any, Options map[string]any) {
    var AgentResponse = map[string]map[string]interface{}{
        "Head": {
            "Type": HeadAgent,
        },
        "Body": {
            "ClientID": ClientID,
            "Type":     BodyAgentBuild,
            "Config":   Config,
            "Options":  Options,
        },
    }

    a.client.Mutex.Lock()
    err := a.client.Conn.WriteJSON(AgentResponse)
    a.client.Mutex.Unlock()

    if err != nil {
        logger.Error("Failed to write json to websocket: " + err.Error())
        return
    }
}

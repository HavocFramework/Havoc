package service

import (
    "Havoc/pkg/demons"
    "Havoc/pkg/events"
    "Havoc/pkg/profile"
    "github.com/gin-gonic/gin"
    "github.com/gorilla/websocket"
)

type ClientService struct {
    Conn      *websocket.Conn
    Responses map[string]chan []byte
}

type TeamAgentsInterface interface {
    AppendAgent(agent *demons.Agent) []*demons.Agent
}

type ConfigService struct {
    Endpoint string
    Name     string
    Password string
}

type Service struct {
    engine  *gin.Engine
    clients []*ClientService

    Config profile.ServiceConfig

    Events     events.EventInterface
    TeamAgents TeamAgentsInterface
    Agents     []*AgentService
    Data       struct {
        ServerAgents *demons.Agents
    }
}

const (
    HeadRegister      = "Register"
    HeadRegisterAgent = "RegisterAgent"
    HeadAgent         = "Agent"

    BodyAgentRegister = "AgentRegister"
    BodyAgentTask     = "AgentTask"
    BodyAgentResponse = "AgentResponse"
    BodyAgentOutput   = "AgentOutput"
    BodyAgentBuild    = "AgentBuild"
)

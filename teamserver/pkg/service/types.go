package service

import (
	"Havoc/pkg/agent"
	"Havoc/pkg/packager"
	"Havoc/pkg/profile"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

type ClientService struct {
	Conn      *websocket.Conn
	Mutex     sync.Mutex
	Responses map[string]chan []byte
}

type Teamserver interface {
	AgentAdd(agent *agent.Agent) []*agent.Agent

	ListenerServiceExc2Add(Name, ExEndpoint string, client *ClientService) error
	ListenerStartNotify(Listener map[string]any)

	EventAppend(pk packager.Package) []packager.Package
	EventBroadcast(FromUser string, pk packager.Package)
	SendEvent(id string, pk packager.Package) error
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

	Teamserver Teamserver
	Agents     []*AgentService
	Listeners  []*ListenerService
	Data       struct {
		ServerAgents *agent.Agents
	}
}

const (
	HeadRegister      = "Register"
	HeadRegisterAgent = "RegisterAgent"
	HeadAgent         = "Agent"
	HeadListener      = "Listener"

	BodyAgentRegister = "AgentRegister"
	BodyAgentTask     = "AgentTask"
	BodyAgentResponse = "AgentResponse"
	BodyAgentOutput   = "AgentOutput"
	BodyAgentBuild    = "AgentBuild"

	BodyListenerAdd      = "ListenerAdd"
	BodyListenerExC2     = "ListenerAddExC2"
	BodyListenerStart    = "ListenerStart"
	BodyListenerShutdown = "ListenerShutdown"
	BodyListenerTransmit = "ListenerTransmit"
)

func (c *ClientService) WriteJson(v any) error {
	var err error

	c.Mutex.Lock()
	err = c.Conn.WriteJSON(v)
	c.Mutex.Unlock()

	return err
}

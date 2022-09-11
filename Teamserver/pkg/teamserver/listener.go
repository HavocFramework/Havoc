package teamserver

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/Cracked5pider/Havoc/teamserver/pkg/demons"
	"github.com/Cracked5pider/Havoc/teamserver/pkg/events"
	"github.com/Cracked5pider/Havoc/teamserver/pkg/handlers"
	"github.com/Cracked5pider/Havoc/teamserver/pkg/logger"
	"github.com/Cracked5pider/Havoc/teamserver/pkg/packager"
	"github.com/fatih/structs"
)

// TODO: refactor this
func (t *Teamserver) StartListener(ListenerType int, info any) error {

	var (
		CtxFunctions 	= demons.RoutineFunc{}
		ListenerConfig 	any
		ListenerName 	string
	)

	CtxFunctions.EventAppend = t.EventAppend
	CtxFunctions.EventBroadcast = t.EventBroadcast
	CtxFunctions.EventNewDemon = events.Demons.NewDemon
	CtxFunctions.AppendDemon = t.Agents.AppendAgent
	CtxFunctions.AppendListener = events.Listener.AddListener

	CtxFunctions.ServiceAgentGet = func(MagicValue int) demons.ServiceAgentInterface {
		for _, agentService := range t.Service.Agents {
			if agentService.MagicValue == fmt.Sprintf("0x%x",MagicValue) {
				return agentService
			}
		}

		logger.Debug("Service agent not found")
		return nil
	}

	CtxFunctions.ServiceAgentExits = func(MagicValue int) bool {
		for _, agentService := range t.Service.Agents {
			if agentService.MagicValue == fmt.Sprintf("0x%x",MagicValue) {
				return true
			}
		}

		logger.Debug("Service agent not found")
		return false
	}

	CtxFunctions.CallbackSize = func(DemonInstance *demons.Agent, i int) {
		var (
			Message = make(map[string]string)
			pk      packager.Package
		)

		Message["Type"] = "Good"
		Message["Message"] = fmt.Sprintf("Send Task to Agent [%v bytes]", i)

		OutputJson, _ := json.Marshal(Message)

		pk = events.Demons.DemonOutput(DemonInstance.NameID, demons.HAVOC_CONSOLE_MESSAGE, string(OutputJson))

		t.EventAppend(pk)
		t.EventBroadcast("", pk)
	}

	CtxFunctions.AgentExists = func(DemonID int) bool {
		for _, demon := range t.Agents.Agents {
			var NameID, err = strconv.ParseInt(demon.NameID, 16, 64)
			if err != nil {
				logger.Debug("Failed to convert demon.NameID to int: " + err.Error())
				return false
			}

			if DemonID == int(NameID) {
				return true
			}
		}
		return false
	}

	CtxFunctions.DemonOutput = func(DemonID string, CommandID int, Output map[string]string) {
		var (
			out, _ 	= json.Marshal(Output)
			pk 		= events.Demons.DemonOutput(DemonID, CommandID, string(out))
		)

		t.EventAppend(pk)
		t.EventBroadcast("", pk)
	}

	CtxFunctions.AgentGetInstance = func(DemonID int) *demons.Agent {
		for _, demon := range t.Agents.Agents {
			var NameID, _ = strconv.ParseInt(demon.NameID, 16, 64)

			if DemonID == int(NameID) {
				return demon
			}
		}
		return nil
	}

	switch ListenerType {

	case handlers.LISTENER_HTTP:
		var HTTPConfig = handlers.NewConfigHttp()
		var config = info.(handlers.HTTPConfig)

		HTTPConfig.Config = config

		HTTPConfig.Config.Secure = config.Secure
		HTTPConfig.RoutineFunc = CtxFunctions

		HTTPConfig.Start()

		ListenerConfig = HTTPConfig
		ListenerName = config.Name

		break

	case handlers.LISTENER_PIVOT_SMB:
		var SmbConfig = handlers.NewPivotSmb()

		SmbConfig.Config = info.(handlers.SMBConfig)
		SmbConfig.RoutineFunc = CtxFunctions

		// this only prints a message and lets the client now that it is ready to use
		SmbConfig.Start()

		ListenerConfig = SmbConfig
		ListenerName = SmbConfig.Config.Name

		break

	case handlers.LISTENER_EXTERNAL:
		var ExtConfig = handlers.NewExternal(t.Server.Engine, info.(handlers.ExternalConfig))

		ExtConfig.RoutineFunc = CtxFunctions

		ExtConfig.Start()

		ListenerConfig = ExtConfig
		ListenerName = info.(handlers.ExternalConfig).Name

		break
	}

	t.Listeners = append(t.Listeners, &Listener{
		Name: ListenerName,
		Type: ListenerType,
		Config: ListenerConfig,
	})

	return nil
}

func (t *Teamserver) ListenerGetInfo(Name string) map[string]any {

	for _, listener := range t.Listeners {
		if listener.Name == Name {
			switch listener.Type {
			case handlers.LISTENER_HTTP:
				return structs.Map(listener.Config.(*handlers.HTTP).Config)

			case handlers.LISTENER_EXTERNAL:
				break

			case handlers.LISTENER_PIVOT_SMB:
				break
			}
		}
	}

	return nil
}

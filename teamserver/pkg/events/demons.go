package events

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"Havoc/pkg/agent"
	"Havoc/pkg/logr"
	"Havoc/pkg/packager"
)

/* TODO: rename everything here from 'Demon' to 'Agent' */

var Demons demons

func (demons) NewDemon(Agent *agent.Agent) packager.Package {
	var (
		Package    packager.Package
	)

	Package.Head.Event = packager.Type.Session.Type
	Package.Head.Time = time.Now().Format("02/01/2006 15:04:05")

	Package.Body.SubEvent = packager.Type.Session.NewSession
	Package.Body.Info = make(map[string]interface{})

	InfoMap := map[string]interface{}{
		"Active": fmt.Sprintf("%v", Agent.Active),
		"BackgroundCheck": Agent.BackgroundCheck,
		"DomainName": Agent.Info.DomainName,
		"Elevated": Agent.Info.Elevated,
		"Encryption": map[string]interface{}{
			"AESKey": base64.StdEncoding.EncodeToString(Agent.Encryption.AESKey),
			"AESIv":  base64.StdEncoding.EncodeToString(Agent.Encryption.AESIv),
		},
		"InternalIP": Agent.Info.InternalIP,
		"ExternalIP": Agent.Info.ExternalIP,
		"FirstCallIn": Agent.Info.FirstCallIn,
		"LastCallIn": Agent.Info.LastCallIn,
		"Hostname": Agent.Info.Hostname,
		"Listener": "null", // ?
		"MagicValue": fmt.Sprintf("%x", Agent.Info.MagicValue),
		"NameID": Agent.NameID,
		"OSArch": Agent.Info.OSArch,
		"OSBuild": Agent.Info.OSBuild,
		"OSVersion": Agent.Info.OSVersion,
		"Pivots": map[string]interface{}{
			"Parent": nil,
			"Links":  []string{},
		},
		"PortFwds": []string{},
		"ProcessArch": Agent.Info.ProcessArch,
		"ProcessName": Agent.Info.ProcessName,
		"ProcessPID": Agent.Info.ProcessPID,
		"ProcessPPID": Agent.Info.ProcessPPID,
		"ProcessPath": Agent.Info.ProcessPath,
		"Reason": Agent.Reason,
		"SleepDelay": Agent.Info.SleepDelay,
		"SleepJitter": Agent.Info.SleepJitter,
		"SocksCli": []string{},
		"SocksCliMtx": nil,
		"SocksSvr": []string{},
		"TaskedOnce": Agent.TaskedOnce,
		"Username": Agent.Info.Username,
		"PivotParent": "",
	}

	/*
	// BREAKS
	//var InfoMap = structs.Map(Agent)
	InfoMap["Active"] = fmt.Sprintf("%v", Agent.Active)
	InfoMap["BackgroundCheck"] = Agent.BackgroundCheck
	InfoMap["DomainName"] = Agent.Info.DomainName
	InfoMap["Elevated"] = Agent.Info.Elevated
	InfoMap["Encryption"] = map[string]interface{}{
		"AESKey": base64.StdEncoding.EncodeToString(Agent.Encryption.AESKey),
		"AESIv":  base64.StdEncoding.EncodeToString(Agent.Encryption.AESIv),
	}
	InfoMap["InternalIP"] = Agent.Info.InternalIP
	InfoMap["ExternalIP"] = Agent.Info.ExternalIP
	InfoMap["FirstCallIn"] = Agent.Info.FirstCallIn
	InfoMap["LastCallIn"] = Agent.Info.LastCallIn
	InfoMap["Hostname"] = Agent.Info.Hostname
	InfoMap["Listener"] = "null" // ?
	InfoMap["MagicValue"] = fmt.Sprintf("%x", Agent.Info.MagicValue)
	InfoMap["NameID"] = Agent.NameID
	InfoMap["OSArch"] = Agent.Info.OSArch
	InfoMap["OSBuild"] = Agent.Info.OSBuild
	InfoMap["OSVersion"] = Agent.Info.OSVersion
	InfoMap["Pivots"] = map[string]interface{}{
		"Parent": nil,
		"Links":  []string{},
	}
	InfoMap["PortFwds"] = []string{}
	InfoMap["ProcessArch"] = Agent.Info.ProcessArch
	InfoMap["ProcessName"] = Agent.Info.ProcessName
	InfoMap["ProcessPID"] = Agent.Info.ProcessPID
	InfoMap["ProcessPPID"] = Agent.Info.ProcessPPID
	InfoMap["ProcessPath"] = Agent.Info.ProcessPath
	InfoMap["Reason"] = Agent.Reason
	InfoMap["SleepDelay"] = Agent.Info.SleepDelay
	InfoMap["SleepJitter"] = Agent.Info.SleepJitter
	InfoMap["SocksCli"] = []string{}
	InfoMap["SocksCliMtx"] = nil
	InfoMap["SocksSvr"] = []string{}
	InfoMap["TaskedOnce"] = Agent.TaskedOnce
	InfoMap["Username"] = Agent.Info.Username
	InfoMap["Listener"] = nil
	*/
	if Agent.Pivots.Parent != nil {
		InfoMap["PivotParent"] = Agent.Pivots.Parent.NameID
	}

	Package.Body.Info = InfoMap

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

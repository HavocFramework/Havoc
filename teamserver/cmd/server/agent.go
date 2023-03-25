package server

import (
	"Havoc/pkg/logger"
	"encoding/json"
	"fmt"
	"strconv"

	"Havoc/pkg/agent"
	"Havoc/pkg/events"
	"Havoc/pkg/packager"
)

func (t *Teamserver) AgentUpdate(agent *agent.Agent) {
	err := t.DB.AgentUpdate(agent)
	if err != nil {
		logger.Error("Could not update agent: " + err.Error())
	}
}

func (t *Teamserver) ParentOf(Agent *agent.Agent) (int, error) {
	var AgentID, _ = strconv.ParseInt(Agent.NameID, 16, 64)

	ID, err := t.DB.ParentOf(int(AgentID))
	return ID, err
}

func (t *Teamserver) LinksOf(Agent *agent.Agent) []int {
	var AgentID, _ = strconv.ParseInt(Agent.NameID, 16, 64)

	return t.DB.LinksOf(int(AgentID))
}

func (t *Teamserver) LinkAdd(ParentAgent *agent.Agent, LinkAgent *agent.Agent) error {
	var ParentAgentID, _ = strconv.ParseInt(ParentAgent.NameID, 16, 64)
	var LinkAgentID,   _ = strconv.ParseInt(LinkAgent.NameID, 16, 64)

	err := t.DB.LinkAdd(int(ParentAgentID), int(LinkAgentID))
	if err != nil {
		logger.Error("Could not add link to database: " + err.Error())
	}

	return nil
}

func (t *Teamserver) LinkRemove(ParentAgent *agent.Agent, LinkAgent *agent.Agent) error {
	var ParentAgentID, _ = strconv.ParseInt(ParentAgent.NameID, 16, 64)
	var LinkAgentID,   _ = strconv.ParseInt(LinkAgent.NameID, 16, 64)

	err := t.DB.LinkRemove(int(ParentAgentID), int(LinkAgentID))
	if err != nil {
		logger.Error("Could not remove link to database: " + err.Error())
	}

	return nil
}

func (t *Teamserver) AgentHasDied(Agent *agent.Agent) bool {
	var AgentID, _ = strconv.ParseInt(Agent.NameID, 16, 64)

	return t.DB.AgentHasDied(int(AgentID))
}

func (t *Teamserver) AgentAdd(Agent *agent.Agent) []*agent.Agent {
	if Agent != nil {
		if t.WebHooks != nil {
			t.WebHooks.NewAgent(Agent.ToMap())
		}
	}

	err := t.DB.AgentAdd(Agent)
	if err != nil {
		logger.Error("Could not add agent to database: " + err.Error())
	}

	return t.Agents.AgentsAppend(Agent)
}

func (t *Teamserver) AgentSendNotify(Agent *agent.Agent) {

	var pk packager.Package

	/* create a new agent package */
	pk = t.EventNewDemon(Agent)

	/* append the new agent event */
	t.EventAppend(pk)

	/* send it to every connected client */
	t.EventBroadcast("", pk)

}

func (t *Teamserver) AgentCallbackSize(DemonInstance *agent.Agent, i int) {
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

func (t *Teamserver) AgentInstance(AgentID int) *agent.Agent {
	for _, demon := range t.Agents.Agents {
		var NameID, _ = strconv.ParseInt(demon.NameID, 16, 64)

		if AgentID == int(NameID) {
			return demon
		}
	}
	return nil
}

func (t *Teamserver) AgentLastTimeCalled(AgentID string, Time string, LastCallback string, Sleep int, Jitter int, KillDate int64, WorkingHours int32) {
	var (
		Output = map[string]string{
			"Diff": Time,
			"Last": LastCallback,
			"Sleep": fmt.Sprintf("%d", Sleep),
			"Jitter": fmt.Sprintf("%d", Jitter),
			"KillDate": fmt.Sprintf("%d", KillDate),
			"WorkingHours": fmt.Sprintf("%d", WorkingHours),
		}

		out, _ = json.Marshal(Output)
		pk     = events.Demons.DemonOutput(AgentID, agent.COMMAND_NOJOB, string(out))
	)

	t.EventBroadcast("", pk)
}

func (t *Teamserver) AgentExist(AgentID int) bool {
	for _, demon := range t.Agents.Agents {
		var NameID, err = strconv.ParseInt(demon.NameID, 16, 64)
		if err != nil {
			logger.Debug("Failed to convert demon.NameID to int: " + err.Error())
			return false
		}

		if AgentID == int(NameID) {
			return true
		}
	}
	return false
}

func (t *Teamserver) AgentConsole(AgentID string, CommandID int, Output map[string]string) {
	var (
		out, _ = json.Marshal(Output)
		pk     = events.Demons.DemonOutput(AgentID, CommandID, string(out))
	)

	t.EventAppend(pk)
	t.EventBroadcast("", pk)
}

func (t *Teamserver) PythonModuleCallback(ClientID string, AgentID string, CommandID int, Output map[string]string) {
	var (
		out, _ = json.Marshal(Output)
		pk     = events.Demons.DemonOutput(AgentID, CommandID, string(out))
	)

	err := t.SendEvent(ClientID, pk)
	if err != nil {
		logger.Error("SendEvent error: ", err)
	}
}

func (t *Teamserver) AgentCallback(DemonID string, Time string) {
	var (
		Output = map[string]string{
			"Output": Time,
		}

		out, _ = json.Marshal(Output)
		pk     = events.Demons.DemonOutput(DemonID, agent.COMMAND_NOJOB, string(out))
	)

	t.EventBroadcast("", pk)
}

package server

import (
	"Havoc/pkg/agent"
	"Havoc/pkg/logger"
	"fmt"
)

func (t *Teamserver) ServiceAgent(MagicValue int) agent.ServiceAgentInterface {
	for _, agentService := range t.Service.Agents {
		if agentService.MagicValue == fmt.Sprintf("0x%x", MagicValue) {
			return agentService
		}
	}

	logger.Debug("Service agent not found")
	return nil
}

func (t *Teamserver) ServiceAgentExist(MagicValue int) bool {
	for _, agentService := range t.Service.Agents {
		if agentService.MagicValue == fmt.Sprintf("0x%x", MagicValue) {
			return true
		}
	}

	logger.Debug("Service agent not found")
	return false
}

package handlers

import (
    "Havoc/pkg/colors"
    "Havoc/pkg/logger"
)

func NewPivotSmb() *SMB {
    var Smb = new(SMB)

    return Smb
}

func (s *SMB) Start() {
    logger.Info("Started \"" + colors.Green(s.Config.Name) + "\" listener")

    pk := s.RoutineFunc.AppendListener("", LISTENER_PIVOT_SMB, s)
    s.RoutineFunc.EventAppend(pk)
    s.RoutineFunc.EventBroadcast("", pk)
}

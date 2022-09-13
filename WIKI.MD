# Havoc

Havoc is a modern and malleable post-exploitation command and control framework.

#### Table of Contents
- [Known Issues](#kissues)
- [Installation](#install)
	- [Building the Client](#bclient)
	- [Building the Teamserver](#bteam)
- [Teamserver](#teamserver)
	- [Starting the Teamserver](#stt)
	- [Arguments](#targ)
	- [Profiles](#profiles)
		- [Teamserver](#pteam)
		- [Operators](#pops)
	- [Demon](#pdemon)
	- [Listeners](#plisten)
- [Client](#client)
	- [Starting the client](#cstc)
	- [Connecting to the Teamserver](#cctt)
- [Agents](#agents)
	- [Demon](#ademon)
		- [Generating a Demon Payload](#adgen)
		- [Layout](#adlay)
		- [Features](#adft)
		- [Commands](#adcmds)
- [External C2](#extc2)
- [Custom Agents](#ca)
- [Python API](#pyapi)
- [Modules](#modules)
- [FAQ](#faq)
- [TODO](#todo)
--------------------


## <a name="kissues"></a>Known Issues

> See the Issues tab for all open issues. 

**Kali Linux**

Kali has issues loading the proper font (Monaco) from the embedeed Qt resources file.

_You will experience formatting issues in the Havoc client if you are not using a monospace/fixed-width font!_

---

## <a name="install"></a>Installation

### <a name="bclient"></a>Building the Client

> If you are using a debian-based distro, you can use the bundled installation script at `/Havoc/Client/Install.sh`. 


Kali/Debian/Ubuntu:
```
sudo apt update
sudo apt install golang-go qtbase5-dev libqt5websockets5-dev libspdlog-dev python3-dev libboost-all-dev mingw-w64 nasm cmake -y
```

Clone the repository:
```
git clone https://github.com/HavocFramework/Havoc.git
```

Build and Run:
```
cd Havoc/Client
mkdir Build
cd Build
cmake ..
cd ..
./Havoc.sh
```

Running `Havoc.sh` will automatically build the Client and start it. 

### <a name="bteam"></a>Building the Teamserver

> If you are using a debian-based distro, you can use the bundled installation script at `/Havoc/Teamserver/Install.sh`


Install additional Go dependencies:
```
cd Havoc/Teamserver

go mod download golang.org/x/sys  
go mod download github.com/ugorji/go
```

Build and Run:
```
cd Havoc/Teamserver
make
./bin/teamserver -h
``` 

---

## <a name="teamserver"></a>Teamserver

The Havoc Teamserver is written in Golang. It handles the listeners, teamserver authentication and payload generation. It also supports ExternalC2 functionality through the configuration of Service endpoints.

### <a name="stt"></a> Starting the Teamserver

> A script is included to automatically start the Teamserver using some default options: `Havoc/Teamserver/teamserver`.

Running `./teamserver` will automatically build the Teamserver, set it as executable and start it with the following options:

`./bin/teamserver server --profile profiles/havoc.yaotl -v`

### <a name="targ"></a>Arguments

Usage: `teamserver [command] [flags]`

Here is a full list of arguments that can be passed to the teamserver:

| Command  | Flag | Description | Args |
| -------- | ---- | ----------- | ----- |
| `server` |`--profile` | The configuration profile to load at start | Teamserver profile path (`string`) |
|  | `-v` / `--verbose` | Enable verbose output | |
|  | `-d` / `--debug` | Enable debug ouput | |
|  | `-h` / `--help` | Output server help | |
|  | `--debug-dev` | Enables DEBUG output (see below for caveats) | |

#### Enabling DEBUG Output

> DEBUG output can be enabled by passing the `--debug-dev` flag to the Teamserver.

When this flag is set, the Teamserver's `builder` class adds the `-D DEBUG` flag to the `builder.compilerOptions.CFlags` array and removes the `-nostdlib` flag to enable output to be printed to the console. Demon agent payloads genereated from the Havoc client will print visible DEBUG text in the console window after execution. The stdlib will be linked into the payload for this to occur, increasing the payload size.

### <a name="tprofiles"></a>Profiles

Havoc's Teamserver uses profiles in the `yaotl` format, which is a custom configuration syntax built on top of [HCL](https://github.com/hashicorp/hcl).

Profiles are located at: `Havoc/Teamserver/profiles` and can be passed to the `teamserver` with the `--profile <path-to-profile` flag.

The default example profile can be found at `Havoc/Teamserver/profiles/havoc_default.yaotl`.


#### <a name="pteam"></a>Teamserver
The teamserver can be configured to listen on a specific bind address and port with the following directive:

```hcl
Teamserver { 
    Host = "0.0.0.0"
    Port = 40056
}
```

- `Host` - The bind address used by the teamserver to accept Client connections.
- `Port` - The port the teamserver listens on for Client connections.

#### <a name="pops"></a>Operators

Multiple users can be added to the Teamserver with the Operators directive:

```hcl
Operators {
	user "5pider" {
		Password = "password1234"
	}

	user "Neo" {
		Password = "password1234"
	}
}
```

#### <a name="pdemon"></a>Demon

The primary Demon agent accepts a number of configuration options such as:

```hcl
Demon {
    Sleep   = 2
    Jitter  = 20

    Implant {
        SleepMask = 1
        SleepMaskTechnique = 0
    }

    Injection {
        Spawn64 = "C:\\Windows\\System32\\notepad.exe"
        Spawn32 = "C:\\Windows\\SysWOW64\\notepad.exe"
    }
}
```

- `Sleep` - The default interval to sleep between check-ins for commands.
- `Jitter` - The amount of jitter to be applied to sleep intervals (in milliseconds).

- `Implant\SleepMask` - Enables the Sleep Mask obfuscation
- `Implant\SleepMaskTechnique` - Chose from a variety of built-in sleep mask techniques:
    - `0` - [WaitForSingleObjectEx](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobjectex) (no obfuscation)
    - `1` - [FOLIAGE](https://github.com/SecIdiot/FOLIAGE)
    - `2` - [Ekko](https://github.com/Cracked5pider/Ekko)

- `Injection\Spawn64` - The full path to the process to spawn into for fork & run operations (64bit).
- `Injection\Spawn32` - The full path to the process to spawn into for fork & run operations (32bit).

#### <a name="plisten"></a>Listeners

> Currently, only HTTP/HTTPS listeners are supported.

Havoc supports multiple listener profiles and a variety of configuration options to help customize them.

```hcl
Listeners {
    Http {
        Name        = "HTTPS Listener"
        Host        = "10.0.0.10"
        Port        = 443
        Method      = "POST"
        Secure      = true
        UserAgent   = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
        Uris        = [
            "/funny_cat.gif",
            "/index.php",
            "/test.txt",
            "/helloworld.js"
        ]
        Headers     = [
            "X-Havoc: true",
            "X-Havoc-Agent: Demon",
        ]

        Response {
            Headers = [
                "Content-type: text/plain",
                "X-IsHavocFramework: true",
            ]
        }

    }
}
```

---

## <a name="client"></a>Client

The Havoc Client is written in C++ and Qt.

### <a name="cstc"></a>Starting the Client

```
cd Havoc/Client
./Havoc.sh
```

The `Havoc.sh` script will automatically build the Client and execute it afterwards.

### <a name="cctt"></a>Connecting to the Teamserver

When the client opens, you will be presented with a profile window similar to that in other C2 frameworks like Cobalt Strike. 

Enter the profile name, teamserver bind address (`Host`) and `Port`, along with your defined username/password in the teamserver profile.

---

## <a name="agents"></a>Agents

### <a name="ademon"></a>Demon

Demon is the primary Havoc agent, written in C/ASM. The source-code is located at `Havoc/Teamserver/data/implants/Demon`.

#### <a name="adgen"></a>Generating a Demon Payload

> Currently, only x64 EXE/DLL formats are supported.

From the Havoc UI, nagivate to `Attack -> Payload`. 

#### <a name="adlay"></a>Layout

| Directory       | Description                                           |
| --------------- | ----------------------------------------------------- |
| `Source/Asm`    | Assembly code (return address stack spoofing)         |
| `Source/Core`   | Core functionality (transport, win32 apis, syscalls)  |
| `Source/Crypt`  | AES/XOR encryption functionality                      |
| `Source/Extra`  | KaynLdr (reflective loader)                           |
| `Source/Inject` | Injection functionality                               |
| `Source/Loader` | COFF Loader, Beacon API                               |
| `Source/Main`   | PE/DLL/RDLL Entry Points                              |

#### <a name="adft"></a> Features

##### Indirect Syscalls

When compiled with `OBF_SYSCALL`, Demon performs indirect syscalls for many Nt* APIs. By masquerading the `RIP` to point to a location within `ntdll.dll`, traps placed by EDR solutions (such as process instrumentation callbacks or other forms of sycall tracing)may be evaded. 

The Syscall logic is primarily contained within `/Teamserver/data/implants/Demon/Source/Core/Syscalls.c`

Syscall stubs are dynamically crafted from ntdll.dll on disk and modified so the return address points to `NtAddBootEntry (0x180024b6)` within the ntdll.dll module.

#### <a name="adcmds"></a>Commands

Demon has a variety of commands built-in. It also supports the dynamic modification of configuration at runtime, allowing operators to customize defaults pre-set in the profiles throughout an engagement, without modifying the profile and re-generating a payload.

Full documentation on commands can be accessed from the Havoc client by typing `help` in the interact window. For more information on a particular command, simply tack it on the end of help like so: `help [command]`

##### `checkin`

> Results from this command are not yet fully implemented.

Requests a checkin request from the Demon. This will output some basic system/configuration information to the Havoc client such as:

- Demon Metadata
    - Magic values
    - First/Last call in timestamps
    - AES Key and IV
    - Sleep Delay
- Host Information
    - Hostname
    - Username
    - Domain Name
    - Internal IP(s)
- Process Information
    - Name
    - Architecture
    - PID
    - Path
    - Elevated
- Operating System
    - Version
    - Build
    - Architecture

##### `sleep`

Demon supports sleeping at a specified delay (seconds) with a randomized jitter amount applied in the profile configuration settings.

`sleep [delay]`

When the Demon sleeps, it first checks if Sleep Masking is enabled in the profile configuration. If so, as long as there are no active job threads running, it will begin to apply the specified sleep obfuscation method and wait until the provided delay to "wake up" and check-in to the teamserver again.

During sleep, x64 demons may implement [return address spoofing](https://www.unknowncheats.me/forum/anti-cheat-bypass/268039-x64-return-address-spoofing-source-explanation.html) to hide the real return address.

##### `job`

Demon implements a multi-threaded job management system that allows the operator to manage long-running tasks. 

> OPSEC NOTE: Long-running jobs will PREVENT sleep obfuscation from occuring at the specified sleep interval due to the other threads running. Sleep obfuscation will only occur when there are no job threads in a running state.

- `job list` - Lists all running jobs.
- `job suspend 1` - Suspends a job with the ID of 1
- `job resume 1` - Resumes a job with the ID of 1
- `job kill 1` - Kills a job with the ID of 1

##### `proc`

Process management and enumeration system.

`proc [command]`

- `proc list` - Display a list of running processes on the target.
- `proc kill [pid]` - Kills a process with the specified PID
- `proc blockdll [on|off]` - Blocks the loading of DLLs that aren't signed by Microsoft using Process Mitigation Policies

##### `token`

Demon implements a token management vault that allows for token theft, impersonation and privilege modification. All tokens are preserved within a token vault, allowing the operator to list and impersonate any stolen token when convenient.

> Tokens are duplicated using `SecurityIdentification` and `SecurityImpersonate` privileges, allowing `OpenThreadToken` to work on impersonated UIDs with OpenAsSelf set to TRUE.

- `token getuid` - Prints the current user id from the token
- `token list` - List all stolen tokens in the token vault
- `token steal [pid]` - Steal the token from the specified PID and save it to the token vault
- `token impersonate [id]` - Impersonate a token from the token vault
- `token make [domain] [username] [password]` - Creates a token from the specified credentials and adds it to the vault
- `token privs-get` - Attempt to acquire all privileges from the current token
- `token privs-list` - List all privileges from the current token
- `token revert` - Reverts back to the default process token
- `token remove [id]` - Removes a token from the vault
- `token clear` - Removes all tokens from the vault.

(INCOMPLETE)

---

## <a name="extc2"></a>ExternalC2

Havoc supports custom agents and ExternalC2 by using Teamserver service endpoints. These are configured using `Service` directives (see the Teamserver Profiles documentation).

The Service module is for interacting with external services (custom agents, ExternalC2, etc). 

By registering a Service directive, the Teamserver will automatically spawn a service listener that can route commands to/from the Teamserver.

```hcl
Service {
    Endpoint = "service-endpoint"
    Password = "service-password"
}
```

This would create a service endpoint at `<teamserver-host>:<teamserver-port>/service-endpoint` that is authenticated with `service-password`. 


## <a name="ca"></a>Custom Agents

Using Havoc's Service API, custom, third-party agents can be written to interact with the teamserver using the intermediate Python API.

An example of a third-party agent is provided here: [https://github.com/HavocFramework/Talon](https://github.com/HavocFramework/Talon)

`Talon.py` connects to the Teamserver over the `Endpoint` defined in the `Service` directive of the teamserver profile.

```python
from havoc.service import HavocService
from havoc.agent import *

class MyCustomAgent(AgentType):
    # ...
    pass

agent = MyCustomAgent()

havoc_service = HavocService(
    endpoint="ws://0.0.0.0:40056/service-endpoint",
    password="service-password"
)

havoc_service.register_agent(agent)
```

Custom commands can be defined using the Python API and extending the Command class:

```python
class CommandShell(Command):
    CommandId = COMMAND_SHELL
    Name = "shell"
    Description = "executes commands using cmd.exe"
    Help = ""
    NeedAdmin = False
    Params = [
        CommandParam(
            name="commands",
            is_file_path=False,
            is_optional=False
        )
    ]
    Mitr = []

    def job_generate( self, arguments: dict ) -> bytes:        
        Task = Packer()

        Task.add_int( self.CommandId )
        Task.add_data( "c:\windows\system32\cmd.exe /c " + arguments[ 'commands' ] )

        return Task.buffer
```

---

## <a name="pyapi"></a>Python API


[https://github.com/HavocFramework/havoc-py](https://github.com/HavocFramework/havoc-py)

---

## <a name="modules"></a>Modules

Aside from Havoc's built-in commands, Modules can be loaded into the framework to add more functionality.

An example of some of Havoc's official modules can be found at this repository:

[https://github.com/HavocFramework/Modules](https://github.com/HavocFramework/Modules)


Module Template: [https://github.com/HavocFramework/Modules/tree/main/Template](https://github.com/HavocFramework/Modules/tree/main/Template)


Official Modules:
- Powerpick
    - Executes unmanaged PowerShell commands by loading the CLR runtime (`4.0.30319`) into the designated fork & run process.
- InvokeAssembly
    - Executes a dotnet assembly into a separate process by bootsrapping the CLR into the designated fork & run process and passing the arguments.
    - The dotnet version can be specified in the arguments (`v4.0.30319` is default), as well as the AppDomain name (`DefaultAppDomain` is default).


---

## <a name="faq"></a>FAQ

### Why does Havoc not perform sleep obfuscation when jobs are running?
Jobs are ran in their own threads, and sleep obfuscation requires that all threads are suspended in order to encrypt the heap, otherwise the process would crash. 

---

## <a name="todo"></a>TODO

- Write up all Demon command documentation (waiting for cmd changes to finalize)
- Show more profile config examples for other Demon config opts
- Finish Listener opt description table
- Finish Modules documentation (how to compile and load a module)
- Finish EXTC2/Custom Agent/Python API docs
- Add FAQ
- Add Screenshots

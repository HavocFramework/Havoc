# Havoc

Havoc is a modern and malleable post-exploitation command and control framework.

## Known Issues

> See the Issues tab for all open issues. 

**Kali Linux**

Kali Linux has issues loading the proper font (Monaco) from the embedeed Qt resources file. This appears to be a known qt5 issue and may be due to the qt5-default package on Kali not being build with `-fontconfig`. You will experience formatting issues in the Havoc client if you are not using a monospace/fixed-width font.

As a workaround you could attempt to build Qt5 from source with `-fontconfig` manually.

---

## Installation

### Building the Client

> If you are using a debian-based distro, you can attempt to use the built-in installation script at `/Havoc/Client/Install.sh`. 


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

### Building the Teamserver

> If you are using a debian-based distro, you can attempt to use the bundled installation script at `/Havoc/Teamserver/Install.sh`


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

## Teamserver

The Havoc Teamserver is written in Golang. It handles the listeners, teamserver authentication and payload generation.

### Starting the Teamserver

> A script is included to automatically start the Teamserver using some default options: `Havoc/Teamserver/teamserver`.

Running `./teamserver` will automatically build the Teamserver, set it as executable and start it with the following options:

`./bin/teamserver server --profile profiles/havoc.yaotl -v`

### Arguments

View help: `./bin/teamserver -h`
Usage: `teamserver [command] [flags]`

Here is a full list of arguments that can be passed to the teamserver:

| Command  | Flag | Description | Args |
| -------- | ---- | ----------- | ----- |
| `server` |`--profile` | The configuration profile to load at start | Teamserver profile path (`string`) |
|  | `-v` / `--verbose` | Enable verbose output | |
|  | `-d` / `--debug` | Enable debug ouput | |
|  | `-h` / `--help` | Output server help | |

### Teamserver Profiles

Havoc's Teamserver uses profiles in the `yaotl` format, which is a custom configuration syntax built on top of [HCL](https://github.com/hashicorp/hcl).

Profiles are located at: `Havoc/Teamserver/profiles` and can be passed to the `teamserver` with the `--profile <path-to-profile` flag.

The default example profile can be found at `Havoc/Teamserver/profiles/havoc_default.yaotl`.


#### Teamserver
The teamserver can be configured to listen on a specific bind address and port with the following directive:

```hcl
Teamserver { 
    Host = "0.0.0.0"
    Port = 40056
}
```

- `Host` - The bind address used by the teamserver to accept Client connections.
- `Port` - The port the teamserver listens on for Client connections.

#### Operators

Multiple users can be added to the Teamserver with the Operators directive:

```hcl
Operators {
	user "Havoc" {
		Password = "Password1234"
	}

	user "Neo" {
		Password = "WhiteRabbit"
	}
}
```

#### Demon

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
    - `3` - [Ace](https://github.com/kyleavery/AceLdr)

- `Injection\Spawn64` - The full path to the process to spawn into for fork & run operations (64bit).
- `Injection\Spawn32` - The full path to the process to spawn into for fork & run operations (32bit).

#### Listeners

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

## Client

The Havoc Client is written in C++ and Qt.

### Starting the Client

```
cd Havoc/Client
./Havoc.sh
```

The `Havoc.sh` script will automatically build the Client and execute it afterwards.

### Connecting to the Teamserver

When the client opens, you will be presented with a profile window similar to that in Cobalt Strike. 



---

## Agents

### Demon

Demon is the primary Havoc agent, written in C/ASM. The source-code is located at `Havoc/Teamserver/data/implants/Demon`.

#### Generating a Demon Payload

> Currently, only x64 EXE/DLL formats are supported.

From the Havoc UI, nagivate to `Attack -> Payload`. 

#### Layout

| Directory       | Description                                           |
| --------------- | ----------------------------------------------------- |
| `Source/Asm`    | Assembly code (return address stack spoofing)         |
| `Source/Core`   | Core functionality (transport, win32 apis, syscalls)  |
| `Source/Crypt`  | AES/XOR encryption functionality                      |
| `Source/Extra`  | KaynLdr (reflective loader)                           |
| `Source/Inject` | Injection functionality                               |
| `Source/Loader` | COFF Loader, Beacon API                               |
| `Source/Main`   | PE/DLL/RDLL Entry Points                              |


#### Commands

| Command | Type | Description |
| ------- | ------ | ----------- |
| `help` | Command | Shows help message of specified command |


#### Enable DEBUG Output
To build a demon payload with DEBUG output enabled, edit the following file:

`/Teamserver/pkg/common/builder/builder.go`

Under the `builder.compilerOptions.CFlags` array, add the `-D DEBUG` flag. 

> You must remove `-nostdlib` for the output to be printed to the console.

Rebuild the Teamserver using `make` and generate a new payload.

---

## ExternalC2

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


## Custom Agents

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

Commands can be defined using the Python API.

```python


```

---

## Python API


[https://github.com/HavocFramework/havoc-py](https://github.com/HavocFramework/havoc-py)

---

## Modules

Aside from Havoc's built-in commands, Modules can be loaded into the framework to add more functionality.

An example of some of Havoc's official modules can be found at this repository:

[https://github.com/HavocFramework/Modules](https://github.com/HavocFramework/Modules)


Module Template: [https://github.com/HavocFramework/Modules/tree/main/Template](https://github.com/HavocFramework/Modules/tree/main/Template)


Official Modules:
- Powerpick
    - Executes unmanaged PowerShell commands by loading the CLR runtime (`4.0.30319`) into the designated fork&run process.
- InvokeAssembly
    - Executes a dotnet assembly into a separate process by bootsrapping the CLR and passing the arguments.
    - The dotnet version can be specified in the arguments (`v4.0.30319` is default), as well as the AppDomain name (`DefaultAppDomain` is default).


---

## FAQ

---

## TODO

- Write up all Demon command documentation
- Show more profile config examples for other Demon config opts
- Finish Listener opt description table
- Finish Modules documentation (how to compile and load a module)
- Finish EXTC2/Custom Agent/Python API docs
- Add FAQ
- Add Screenshots

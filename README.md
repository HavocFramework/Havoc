<div align="center">
  <img width="125px" src="assets/Havoc.png" />
  <h1>Havoc</h1>
  <br/>

  <p><i>Havoc is a modern and malleable post-exploitation command and control framework, created by <a href="https://twitter.com/C5pider">@C5pider</a>.</i></p>
  <br />

  <img src="assets/Screenshots/FullSessionGraph.jpeg" width="90%" /><br />
  <img src="assets/Screenshots/MultiUserAgentControl.png" width="90%" /><br />

</div>

>[!caution]
>Havoc is in an early state of release. Breaking changes may be made to APIs/core structures as the framework matures.

### Support

Consider supporting C5pider on [Patreon](https://www.patreon.com/5pider)/[Github Sponsors](https://github.com/sponsors/Cracked5pider). Additional features are planned for supporters in the future, such as custom agents/plugins/commands/etc.

### Quick Start

>[!note]
>Please see the [Wiki](https://github.com/HavocFramework/Havoc/wiki) for complete documentation.

Havoc works well on Debian 10/11, Ubuntu 20.04+ and Kali Linux. It's recommended to use the latest versions possible to avoid issues. You'll need a modern version of Qt and Python 3.10.x to build the project.

See the [Installation](https://havocframework.com/docs/installation) docs for instructions. If you run into issues, check the [Known Issues](https://github.com/HavocFramework/Havoc/wiki#known-issues) page as well as the open/closed [Issues](https://github.com/HavocFramework/Havoc/issues) list.

---

### Features

#### Client

> Cross-platform UI written in C++ and Qt

- Modern, dark theme based on [Dracula](https://draculatheme.com/)
- Table and Graph view for agents
- Feature rich with extensible module support


#### Teamserver

> Written in Golang

- Multiplayer
- Payload generation (exe/shellcode/dll)
- HTTP/HTTPS/SMB listeners
- Customizable C2 profiles
- External C2 Support

#### Demon

> Havoc's flagship agent written in C and ASM

- Sleep Obfuscation via [Ekko](https://github.com/Cracked5pider/Ekko), Ziliean or [FOLIAGE](https://github.com/SecIdiot/FOLIAGE)
- x64 return address spoofing
- Indirect Syscalls for Nt* APIs
- SMB support
- Token vault
- Variety of built-in post-exploitation commands
- Patching Amsi/Etw via Hardware breakpoints
- Proxy library loading
- Stack duplication during sleep.

<div align="center">
  <img src="assets/Screenshots/SessionConsoleHelp.png" width="90%" /><br />
</div>

#### Extensibility

- [External C2](https://github.com/HavocFramework/Havoc/wiki#external-c2)
- Custom Agent Support
  - [Talon](https://github.com/HavocFramework/Talon)
  - [Revenant](https://github.com/0xTriboulet/Revenant)
- [Python API](https://github.com/HavocFramework/havoc-py)
- [Modules](https://github.com/HavocFramework/Modules)
  - [Havoc Modules Store](https://p4p1.github.io/havoc-store/)
- [Malleable Profile Generation](https://github.com/Ghost53574/havoc_profile_generator)

---

### Community

You can join the official [Havoc Discord](https://discord.gg/z3PF3NRDE5) to chat with the community!

### Contributing

To contribute to the Havoc Framework, please review the guidelines in [Contributing.md](https://github.com/HavocFramework/Havoc/blob/main/CONTRIBUTING.MD) and then open a pull-request!

### Note
>[!important]
>Please do not open any issues regarding detection.

The Havoc Framework hasn't been developed to be evasive. Rather it has been designed to be as malleable & modular as possible. Giving the operator the capability to add custom features or modules that evades their targets detection system.

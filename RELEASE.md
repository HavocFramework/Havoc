Because Havoc does not currently publish "releases" on GitHub, this document serves as a historical record of all major revision changes. This information was gathered from the Discord channel and is not all-inclusive of every change made.

# Change History

## Version `0.2` | `Magician's Red`

- added command 'shellcode execute' for self injection / execute shellcode in the current process
- UI/UX Fixes (removed placeholders of Process list)
- UI fix: you couldn't reopen process list / file explorer after closing them. Now you can. 
- added support for long running jobs / commands / modules. 
- fix some things in wiki.

Commit: https://github.com/HavocFramework/Havoc/commit/31db84b432d57d7f5d234791455b18260f00cd40

## Version `0.3` | `Hermit Purple`

- added new session icons
- added lateral movement command 'jump-exec psexec' 
- added lateral movement command 'jump-exec scshell' 
- added service executable payload
- added new python api demon.ProcessCreate 

Commit: https://github.com/HavocFramework/Havoc/commit/db8c75f2510096d848999889f03263013eab3120 

## Version `0.4` | `Silver Chariot`

- Chunked downloading of files
- Threaded inline assembly execution (while sleep obf is still usable)
- reverse port forwarding
- webhooks for discord
- smb agent fixes
- bug fixes

Commit: https://github.com/HavocFramework/Havoc/commit/d98f8b692b9c0fe79b6d153b6f34167589082789 

### Version `0.4.1` | `The Fool`

- Socks4a Proxy 
- bug fixes
- vuln fix in the service api (found by hyperreality)

Commit: https://github.com/HavocFramework/Havoc/commit/133f6ead8085147dc39beb368c41aead2873927e

### Version `0.5` | `Emporer`

- upgraded socks4a to socks5
- improved support for redirectors
- 'Health' tab
- add working hours
- refactored BOF loader
- add several default BOFs
- add kill date
- add sleep jitter
- add kerberos native support
- add incognito 'find-tokens'
- add DLL reflective loader (Kayn)
- refactor TS logs

Commits/PR: https://github.com/HavocFramework/Havoc/pull/310

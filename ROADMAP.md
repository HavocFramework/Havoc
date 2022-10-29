# Havoc Framework Roadmap

- Lateral Movement commands.
  - wmiexec
- Switch between injection techniques via config module (example: `config inject.technique 0`). There is already code for it just gotta make it switchable rn. 
- Add all demon commands to the Havoc client python api.
- Protocol to add:
  - DNS
  - TCP (direct/pivot)
  - Wireguard
- Add some privilege escalation techniques.
- Add UI plugin system (expose the QT library to the python interpreter. maybe write a small wrapper that handles pointers etc. like IDA does it)
- Add global chat for [Adam](https://twitter.com/adamsvoboda) :P (as an optional plugin)
- Encrypt config in implant (AES or RC4? not sure)

I have planned to add more features. if you have any feature requests let me know in my discord server (link in the readme.md) or in my twitter dms.

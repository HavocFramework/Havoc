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
- Encrypt config in implant (AES or RC4? not sure)
- add RSA for AES key exchange to avoid exposing the AES key on init request. adding extra communication security.
- rewrite client backend. for now its single threaded which is not ideal. split it into 3 threads which handles different jobs. [reference](https://twitter.com/C5pider/status/1650926729299460096)
- instead of hardcoding the loaded module scripts into the client load scripst from a config file (json). 

I have planned to add more features. if you have any feature requests let me know in my discord server (link in the readme.md) or in my twitter dms.

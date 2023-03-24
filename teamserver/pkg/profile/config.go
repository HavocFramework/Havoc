package profile

type HavocConfig struct {
	Server    *ServerProfile  `yaotl:"Teamserver,block"`
	Operators *OperatorsBlock `yaotl:"Operators,block"`
	Listener  *Listeners      `yaotl:"Listeners,block"`
	Demon     *Demon          `yaotl:"Demon,block"`
	Service   *ServiceConfig  `yaotl:"Service,block"`
	WebHook   *WebHookConfig  `yaotl:"WebHook,block"`
}

type WebHookDiscordConfig struct {
	WebHook   string `yaotl:"Url"`
	AvatarUrl string `yaotl:"AvatarUrl,optional"`
	UserName  string `yaotl:"User,optional"`
}

type WebHookConfig struct {
	Discord *WebHookDiscordConfig `yaotl:"Discord,block"`
}

type BuildConfig struct {
	Compiler64 string `yaotl:"Compiler64,optional"`
	Compiler86 string `yaotl:"Compiler86,optional"`
	Nasm       string `yaotl:"Nasm,optional"`
}

type ServiceConfig struct {
	Endpoint string `yaotl:"Endpoint"`
	Password string `yaotl:"Password"`
}

type ServerProfile struct {
	Host  string       `yaotl:"Host"`
	Port  int          `yaotl:"Port"`
	Build *BuildConfig `yaotl:"Build,block"`
	// TODO: add WebSocket server config
	// Path for Havoc connection
	// TLS or not
}

type OperatorsBlock struct {
	Users []UsersBlock `yaotl:"user,block"`
}

type UsersBlock struct {
	Name     string `yaotl:"Name,label"`
	Password string `yaotl:"Password"`
	Hashed   bool   `yaotl:"Hashed,optional"`
}

type Listeners struct {
	ListenerHTTP     []*ListenerHTTP     `yaotl:"Http,block"`
	ListenerSMB      []*ListenerSMB      `yaotl:"Smb,block"`
	ListenerExternal []*ListenerExternal `yaotl:"External,block"`
}

type ListenerHTTP struct {
	Name string `yaotl:"Name"`

	// 2006-01-02 15:04:05
	KillDate     string `yaotl:"KillDate,optional"`
	// 8:00-17:00
	WorkingHours string `yaotl:"WorkingHours,optional"`

	Hosts        []string `yaotl:"Hosts"`
	HostBind     string   `yaotl:"HostBind"`
	HostRotation string   `yaotl:"HostRotation"`
	/* Port used by the TS */
	PortBind     int      `yaotl:"PortBind"`
	/* Port used by the agent */
	PortConn     int      `yaotl:"PortConn,optional"`

	/* Methode string `yaotl:"Method,optional"` */

	/* optional fields */
	UserAgent string   `yaotl:"UserAgent,optional"`
	Headers   []string `yaotl:"Headers,optional"`
	Uris      []string `yaotl:"Uris,optional"`
	Secure    bool     `yaotl:"Secure,optional"`

	/* optional sub blocks */
	Cert     *ListenerHttpCerts    `yaotl:"Cert,block"`
	Response *ListenerHttpResponse `yaotl:"Response,block"`
	Proxy    *ListenerHttpProxy    `yaotl:"Proxy,block"`
}

type ListenerSMB struct {
	Name     string `yaotl:"Name"`
	PipeName string `yaotl:"PipeName"`

	// 2006-01-02 15:04:05
	KillDate     string `yaotl:"KillDate,optional"`
	// 8:00-17:00
	WorkingHours string `yaotl:"WorkingHours,optional"`
}

type ListenerExternal struct {
	Name     string `yaotl:"Name"`
	Endpoint string `yaotl:"Endpoint"`
}

type ListenerHttpResponse struct {
	Headers []string `yaotl:"Headers,optional"`
}

type ListenerHttpProxy struct {
	Host string `yaotl:"Host"`
	Port int    `yaotl:"Port"`
	User string `yaotl:"Username"`
	Pass string `yaotl:"Password"`
}

type ListenerHttpCerts struct {
	Cert string `yaotl:"Cert"`
	Key  string `yaotl:"Key"`
}

/* TODO: remove */
type HeaderBlock struct {
	MagicMzX64  string `yaotl:"MagicMz-x64,optional"` // max 2 bytes
	MagicMzX86  string `yaotl:"MagicMz-x86,optional"` // max 2 bytes
	CompileTime string `yaotl:"CompileTime,optional"`

	ImageSizeX64 int `yaotl:"ImageSize-x64,optional"`
	ImageSizeX86 int `yaotl:"ImageSize-x86,optional"`
}

type Binary struct {
	Header *HeaderBlock `yaotl:"Header,block"`
}

type ProcessInjectionBlock struct {
	Spawn64 string `yaotl:"Spawn64,optional"`
	Spawn32 string `yaotl:"Spawn32,optional"`
}

type Demon struct {
	Sleep              int                    `yaotl:"Sleep,optional"`
	Jitter             int                    `yaotl:"Jitter,optional"`
	TrustXForwardedFor bool                   `yaotl:"TrustXForwardedFor,optional"`
	Binary             *Binary                `yaotl:"Binary,block"`
	ProcessInjection   *ProcessInjectionBlock `yaotl:"Injection,block"`
}

package packager

type (
	MiscType struct {
		Type       int
		MessageBox int
	}

	Head struct {
		Event int `json:"Event"`

		User    string `json:"User"`
		Time    string `json:"Time"`
		OneTime string `json:"OneTime"`
	}

	Body struct {
		SubEvent int            `json:"SubEvent"`
		Info     map[string]any `json:"Info"`
	}

	Packager struct{}

	Package struct {
		Head Head
		Body Body
	}

	Types struct {
		InitConnection struct {
			Type int

			OAuthRequest int
			Success      int
			Error        int
			InitInfo     int
			Profile      int
		}

		Listener struct {
			Type int

			Add    int
			Remove int
			Edit   int
			Mark   int
			Error  int
		}

		Chat struct {
			Type             int
			NewMessage       int
			NewListener      int
			NewSession       int
			NewUser          int
			UserDisconnected int
		}

		Credentials struct {
			Type int

			Add    int
			Edit   int
			Remove int
		}

		HostFile struct {
			Type int

			Add    int
			Remove int
		}

		Session struct {
			Type int

			NewSession int
			Input      int
			Output     int
			Remove     int
			MarkAsDead int
		}

		Gate struct {
			Type int

			Staged    int
			Stageless int
			MSOffice  int
		}

		// TODO: remove
		Module struct {
			Type int

			Register int
			Unload   int
			Call     int
		}

		Service struct {
			Type int

			RegisterAgent    int
			RegisterListener int
		}

		Misc struct {
			Type       int
			MessageBox int
		}

		Teamserver struct {
			Type    int
			Log     int
			Profile int
		}
	}
)

var Type = Types{

	InitConnection: struct {
		Type         int
		OAuthRequest int
		Success      int
		Error        int
		InitInfo     int
		Profile      int
	}{
		Type: 0x1,

		Success:      0x1,
		Error:        0x2,
		OAuthRequest: 0x3,
		InitInfo:     0x4,
		Profile:      0x5,
	},

	Listener: struct {
		Type   int
		Add    int
		Remove int
		Edit   int
		Mark   int
		Error  int
	}{
		Type: 0x2,

		Add:    0x1,
		Edit:   0x2,
		Remove: 0x3,
		Mark:   0x4,
		Error:  0x5,
	},

	Chat: struct {
		Type             int
		NewMessage       int
		NewListener      int
		NewSession       int
		NewUser          int
		UserDisconnected int
	}{
		Type:             0x4,
		NewMessage:       0x1,
		NewListener:      0x2,
		NewSession:       0x3,
		NewUser:          0x4,
		UserDisconnected: 0x5,
	},

	Credentials: struct {
		Type   int
		Add    int
		Edit   int
		Remove int
	}{
		Type:   0x3,
		Add:    0x1,
		Edit:   0x2,
		Remove: 0x3,
	},

	HostFile: struct {
		Type   int
		Add    int
		Remove int
	}{
		Type:   0x6,
		Add:    0x1,
		Remove: 0x2,
	},

	Session: struct {
		Type       int
		NewSession int
		Input      int
		Output     int
		Remove     int
		MarkAsDead int
	}{
		Type:       0x7,
		NewSession: 0x1,
		Remove:     0x2,
		Input:      0x3,
		Output:     0x4,
		MarkAsDead: 0x5,
	},

	Gate: struct {
		Type      int
		Staged    int
		Stageless int
		MSOffice  int
	}{
		Type:      0x5,
		Staged:    0x1,
		Stageless: 0x2,
		MSOffice:  0x3,
	},

	Module: struct {
		Type     int
		Register int
		Unload   int
		Call     int
	}{
		Type:     0x6,
		Register: 0x1,
		Unload:   0x2,
		Call:     0x3,
	},

	Misc: struct {
		Type       int
		MessageBox int
	}{
		Type:       0x7,
		MessageBox: 0x1,
	},

	Service: struct {
		Type             int
		RegisterAgent    int
		RegisterListener int
	}{
		Type:             0x9,
		RegisterAgent:    0x1,
		RegisterListener: 0x2,
	},

	Teamserver: struct {
		Type    int
		Log     int
		Profile int
	}{Type: 0x10, Log: 0x1, Profile: 0x2},
}

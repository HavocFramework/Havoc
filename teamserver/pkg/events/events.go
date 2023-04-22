package events

import (
	"Havoc/pkg/logger"
	"encoding/json"
	"net"
	"time"

	"Havoc/pkg/packager"
	"Havoc/pkg/profile"
)

type (
	chatLog    int
	listeners  int
	demons     int
	gate       int
	service    int
	teamserver int
)

func Authenticated(authed bool) packager.Package {

	if authed {
		return packager.Package{
			Head: packager.Head{
				Event: packager.Type.InitConnection.Type,
				Time:  time.Now().Format("02/01/2006 15:04:05"),
			},

			Body: packager.Body{
				SubEvent: packager.Type.InitConnection.Success,
				Info: map[string]any{
					"Message": "Successful Authenticated",
				},
			},
		}
	} else {
		return packager.Package{
			Head: packager.Head{
				Event: packager.Type.InitConnection.Type,
				Time:  time.Now().Format("02/01/2006 15:04:05"),
			},

			Body: packager.Body{
				SubEvent: packager.Type.InitConnection.Error,
				Info: map[string]any{
					"Message": "Wrong Password",
				},
			},
		}
	}

}

func UserAlreadyExits() packager.Package {
	return packager.Package{
		Head: packager.Head{
			Event: packager.Type.InitConnection.Type,
			Time:  time.Now().Format("02/01/2006 15:04:05"),
		},

		Body: packager.Body{
			SubEvent: packager.Type.InitConnection.Error,
			Info: map[string]any{
				"Message": "User already exits",
			},
		},
	}
}

func UserDoNotExists() packager.Package {
	return packager.Package{
		Head: packager.Head{
			Event: packager.Type.InitConnection.Type,
			Time:  time.Now().Format("02/01/2006 15:04:05"),
		},

		Body: packager.Body{
			SubEvent: packager.Type.InitConnection.Error,
			Info: map[string]any{
				"Message": "User doesn't exits",
			},
		},
	}
}

func SendProfile(profile *profile.Profile) packager.Package {
	var (
		JsonBytes []byte
		Addresses string
		addrs     []net.Addr
		err       error
	)

	JsonBytes, err = json.Marshal(*profile.Config.Demon)
	if err != nil {
		logger.DebugError("json.Marshal Error: " + err.Error())
		return packager.Package{}
	}

	addrs, err = net.InterfaceAddrs()
	if err != nil {
		logger.DebugError("net.InterfaceAddrs Error: " + err.Error())
		return packager.Package{}
	}

	for _, address := range addrs {
		if aspnet, ok := address.(*net.IPNet); ok && !aspnet.IP.IsLoopback() {
			if aspnet.IP.To4() != nil {
				if len(Addresses) == 0 {
					Addresses = aspnet.IP.String()
				} else {
					Addresses += ", " + aspnet.IP.String()
				}
			}
		}
	}

	return packager.Package{
		Head: packager.Head{
			Event: packager.Type.InitConnection.Type,
			Time:  time.Now().Format("02/01/2006 15:04:05"),
		},

		Body: packager.Body{
			SubEvent: packager.Type.InitConnection.Profile,
			Info: map[string]any{
				"Demon":         string(JsonBytes),
				"TeamserverIPs": Addresses,
			},
		},
	}
}

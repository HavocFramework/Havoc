package events

import (
	"time"

	"Havoc/pkg/packager"
)

var ChatLog chatLog

func (chatLog) NewUserConnected(User string) packager.Package {
	return packager.Package{
		Head: packager.Head{
			Event: packager.Type.Chat.Type,
			Time:  time.Now().Format("02/01/2006 15:04:05"),
		},

		Body: packager.Body{
			SubEvent: packager.Type.Chat.NewUser,
			Info: map[string]any{
				"User": User,
			},
		},
	}
}

func (chatLog) UserDisconnected(User string) packager.Package {
	return packager.Package{
		Head: packager.Head{
			Event: packager.Type.Chat.Type,
			Time:  time.Now().Format("02/01/2006 15:04:05"),
		},

		Body: packager.Body{
			SubEvent: packager.Type.Chat.UserDisconnected,
			Info: map[string]any{
				"User": User,
			},
		},
	}
}

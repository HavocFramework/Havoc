package events

import (
	"encoding/base64"
	"time"

	"Havoc/pkg/packager"
)

var Gate gate

func (g gate) SendStageless(Format string, payload []byte) packager.Package {
	return packager.Package{
		Head: packager.Head{
			Event: packager.Type.Gate.Type,
			Time:  time.Now().Format("02/01/2006 15:04:05"),
		},

		Body: packager.Body{
			SubEvent: packager.Type.Gate.Stageless,
			Info: map[string]any{
				"PayloadArray": base64.StdEncoding.EncodeToString(payload),
				"Format":       Format,
				"FileName":     Format,
			},
		},
	}
}

func (g gate) SendConsoleMessage(MsgType, text string) packager.Package {
	return packager.Package{
		Head: packager.Head{
			Event: packager.Type.Gate.Type,
			Time:  time.Now().Format("02/01/2006 15:04:05"),
		},

		Body: packager.Body{
			SubEvent: packager.Type.Gate.Stageless,
			Info: map[string]any{
				"MessageType": MsgType,
				"Message":     text,
			},
		},
	}
}

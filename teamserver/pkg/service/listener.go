package service

import (
	"Havoc/pkg/logger"
	"encoding/json"
)

type ListenerService struct {
	Name  string           `json:"Name"`
	Agent string           `json:"Agent"`
	Items []map[string]any `json:"Items"`

	// from where this listener came from.
	client *ClientService `json:"-"`
}

func (l *ListenerService) Start(Info map[string]any) error {

	var Request = map[string]map[string]interface{}{
		"Head": {
			"Type": HeadListener,
		},
		"Body": {
			"Type":     BodyListenerStart,
			"Listener": Info,
		},
	}

	if err := l.client.WriteJson(Request); err != nil {
		logger.Error("Failed to write json to websocket: " + err.Error())
		return err
	}

	return nil
}

func (l *ListenerService) Json() string {
	var JsonString, err = json.Marshal(l)
	if err != nil {
		return ""
	}

	return string(JsonString)
}

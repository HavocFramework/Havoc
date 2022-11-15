package webhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

type WebHook struct {
	Discord struct {
		Avatar string
		User   string
		Url    string
	}
}

func StringPtr(str string) *string {
	return &str
}

func BoolPtr(b bool) *bool {
	return &b
}

func NewWebHook() *WebHook {
	return new(WebHook)
}

func (w *WebHook) NewAgent(agent map[string]any) error {

	if len(w.Discord.Url) > 0 {
		var (
			payload   = new(bytes.Buffer)
			message   Message
			embed     Embed
			field     Field
			AgentInfo map[string]any
		)

		AgentInfo = agent["Info"].(map[string]any)

		message.AvatarUrl = &w.Discord.Avatar
		message.Username = &w.Discord.User
		message.Embeds = new([]Embed)

		embed.Title = StringPtr("New Agent Initialized")
		embed.Fields = new([]Field)

		field.Name = StringPtr("Agent ID")
		field.Value = StringPtr(agent["NameID"].(string))
		field.Inline = BoolPtr(true)
		*embed.Fields = append(*embed.Fields, field)

		field.Name = StringPtr("Username")
		field.Value = StringPtr(AgentInfo["Username"].(string))
		field.Inline = BoolPtr(true)
		*embed.Fields = append(*embed.Fields, field)

		field.Name = StringPtr("Hostname")
		field.Value = StringPtr(AgentInfo["Hostname"].(string))
		field.Inline = BoolPtr(true)
		*embed.Fields = append(*embed.Fields, field)

		field.Name = StringPtr("Internal IP")
		field.Value = StringPtr(AgentInfo["InternalIP"].(string))
		field.Inline = BoolPtr(true)
		*embed.Fields = append(*embed.Fields, field)

		field.Name = StringPtr("Process Path")
		field.Value = StringPtr(AgentInfo["ProcessPath"].(string))
		field.Inline = BoolPtr(true)
		*embed.Fields = append(*embed.Fields, field)

		field.Name = StringPtr("Process Name")
		field.Value = StringPtr(AgentInfo["ProcessName"].(string))
		field.Inline = BoolPtr(true)
		*embed.Fields = append(*embed.Fields, field)

		field.Name = StringPtr("Process ID")
		field.Value = StringPtr(strconv.Itoa(AgentInfo["ProcessPID"].(int)))
		field.Inline = BoolPtr(true)
		*embed.Fields = append(*embed.Fields, field)

		field.Name = StringPtr("Process Arch")
		field.Value = StringPtr(AgentInfo["ProcessArch"].(string))
		field.Inline = BoolPtr(true)
		*embed.Fields = append(*embed.Fields, field)

		field.Name = StringPtr("OS Version")
		field.Value = StringPtr(AgentInfo["OSVersion"].(string))
		*embed.Fields = append(*embed.Fields, field)

		field.Name = StringPtr("OS Arch")
		field.Value = StringPtr(AgentInfo["OSArch"].(string))
		field.Inline = BoolPtr(true)
		*embed.Fields = append(*embed.Fields, field)

		field.Name = StringPtr("First Callback")
		field.Value = StringPtr(AgentInfo["FirstCallIn"].(string))
		*embed.Fields = append(*embed.Fields, field)

		*message.Embeds = append(*message.Embeds, embed)

		err := json.NewEncoder(payload).Encode(message)
		if err != nil {
			return err
		}

		resp, err := http.Post(w.Discord.Url, "application/json", payload)
		if err != nil {
			return err
		}

		if resp.StatusCode != 200 && resp.StatusCode != 204 {
			defer resp.Body.Close()

			responseBody, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}

			return fmt.Errorf(string(responseBody))
		}

		return nil
	}

	return nil
}

func (w *WebHook) SetDiscord(AvatarUrl, User, Url string) {
	w.Discord.Avatar = AvatarUrl
	w.Discord.User = User
	w.Discord.Url = Url
}

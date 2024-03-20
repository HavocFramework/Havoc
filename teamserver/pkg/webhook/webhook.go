package webhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

type WebHook struct {
	Discord struct {
		Avatar string
		User   string
		Url    string
	}

	Mattermost struct {
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
	if len(w.Mattermost.Url) > 0 {
		var (
			payload   = new(bytes.Buffer)
			message   Mattermost_Message
			tableRows []string
			AgentInfo map[string]any
		)

		AgentInfo, ok := agent["Info"].(map[string]interface{})
		if !ok {
			return fmt.Errorf("unable to assert AgentInfo as map[string]interface{}")
		}

		tableRows = append(tableRows, "| Field | Value |")
		tableRows = append(tableRows, "| ----- | ----- |")

		addRow := func(name, value string) {
			tableRows = append(tableRows, fmt.Sprintf("| %s | %s |", name, value))
		}

		addRow("Agent ID", agent["NameID"].(string))
		addRow("Username", AgentInfo["Username"].(string))
		addRow("Hostname", AgentInfo["Hostname"].(string))
		addRow("Domain", AgentInfo["DomainName"].(string))
		addRow("Internal IP", AgentInfo["InternalIP"].(string))
		addRow("Process Path", AgentInfo["ProcessPath"].(string))
		addRow("Process Name", AgentInfo["ProcessName"].(string))
		addRow("Process ID", strconv.Itoa(AgentInfo["ProcessPID"].(int)))
		addRow("Process Arch", AgentInfo["ProcessArch"].(string))
		addRow("OS Version", AgentInfo["OSVersion"].(string))
		addRow("OS Arch", AgentInfo["OSArch"].(string))
		addRow("First Callback", AgentInfo["FirstCallIn"].(string))
		addRow("Elevated", AgentInfo["Elevated"].(string))
		addRow("SleepDelay", strconv.Itoa(AgentInfo["SleepDelay"].(int)))
		addRow("SleepJitter", strconv.Itoa(AgentInfo["SleepJitter"].(int)))

		content := fmt.Sprintf("**New Havoc Callback!**\n\n%s", strings.Join(tableRows, "\n"))
		message.Content = &content

		if len(w.Mattermost.Avatar) > 0 {
			message.AvatarUrl = &w.Mattermost.Avatar
		}

		if len(w.Mattermost.User) > 0 {
			message.Username = &w.Mattermost.User
		}

		err := json.NewEncoder(payload).Encode(message)
		if err != nil {
			return err
		}

		resp, err := http.Post(w.Mattermost.Url, "application/json", payload)
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

func (w *WebHook) SetMattermost(AvatarUrl, User, Url string) {
	w.Mattermost.Avatar = AvatarUrl
	w.Mattermost.User = User
	w.Mattermost.Url = Url
}

package webhook

type Mattermost_Message struct {
	AvatarUrl *string `json:"icon_url,omitempty"`
	Content   *string `json:"text,omitempty"`
	Username  *string `json:"username,omitempty"`
}

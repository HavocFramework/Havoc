package profile

import (
	"Havoc/pkg/colors"
	"Havoc/pkg/logger"
	yaotl "Havoc/pkg/profile/yaotl/hclsimple"
)

type Profile struct {
	Config HavocConfig
}

func NewProfile() *Profile {
	return new(Profile)
}

func (p *Profile) SetProfile(path string, def bool) error {
	err := yaotl.DecodeFile(path, nil, &p.Config)
	if err != nil {
		return err
	}

	if def {
		logger.Info("Use default profile")
	} else {
		logger.Info("Havoc profile:", colors.Blue(path))
	}

	return nil
}

func (p *Profile) ServerHost() string {
	if p.Config.Server != nil {
		return p.Config.Server.Host
	}
	return ""
}

func (p *Profile) ServerPort() int {
	if p.Config.Server != nil {
		return p.Config.Server.Port
	}
	return 0
}

func (p *Profile) ListOfUsernames() []string {
	var Usernames []string

	for _, user := range p.Config.Operators.Users {
		Usernames = append(Usernames, user.Name)
	}

	return Usernames
}

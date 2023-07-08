package profile

import (
	"Havoc/pkg/colors"
	"Havoc/pkg/encoder"
	"Havoc/pkg/logger"
	yaotl "Havoc/pkg/profile/yaotl/hclsimple"
	"os"
)

type Profile struct {
	Config HavocConfig
	Path   string
}

func NewProfile() *Profile {
	return new(Profile)
}

func (p *Profile) SetProfile(path string, def bool) error {
	if path == "" {
		logger.Error("No profile specified. Specify a profile with --profile or choose the standard profile with --default")
		os.Exit(1)
	}
	src := encoder.DecryptFile(path)
	err := yaotl.Decode(path, src, nil, &p.Config)
	if err != nil {
		return err
	}

	if def {
		logger.Info("Use default profile")
	} else {
		logger.Info("Havoc profile:", colors.Blue(path))
	}

	p.Path = path
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

func (p *Profile) ServerPassword() []byte {
	if p.Config.Server.Password != "" {
		return []byte(p.Config.Server.Password)
	}
	return nil
}

func (p *Profile) ListOfUsernames() []string {
	var Usernames []string

	for _, user := range p.Config.Operators.Users {
		Usernames = append(Usernames, user.Name)
	}

	return Usernames
}

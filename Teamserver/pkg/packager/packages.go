package packager

import (
    "encoding/json"

    "github.com/Cracked5pider/Havoc/teamserver/pkg/logger"
)

func NewPackager() *Packager {
    return new(Packager)
}

func (p Packager) CreatePackage(jsonObject string) Package {
    var pk Package

    if err := json.Unmarshal([]byte(jsonObject), &pk); err != nil {
        logger.Error("Error while creating Package struct :: " + err.Error() )
    }

    return pk
}

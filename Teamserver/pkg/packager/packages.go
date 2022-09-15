package packager

import (
    "encoding/json"

    "Havoc/pkg/logger"
)

func NewPackager() *Packager {
    return new(Packager)
}

func (p Packager) CreatePackage(jsonObject string) Package {
    var pk Package

    if err := json.Unmarshal([]byte(jsonObject), &pk); err != nil {
        logger.Error("Error while creating Package struct :: " + err.Error())
    }

    return pk
}

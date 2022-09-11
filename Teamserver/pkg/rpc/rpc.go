package rpc

import (
    "errors"
    "net"
)

type (
    Server struct  {
        IPCPort         int

        Listener        net.Listener
        DispatchEvent   func(EventData Data)
        Clients         []net.Conn
    }

    Client struct {
        IPCPort int

        Conn    net.Conn
    }

    Data struct {
        EventType   int
        EventData   interface{}
    }
)

func NewRPC(sc, port int) (interface{}, error) {

    switch sc {
    case SERVER:
        return NewServer(port)

    case CLIENT:
        return NewClient(port)
    }

    return nil, errors.New("invalid communication type")
}
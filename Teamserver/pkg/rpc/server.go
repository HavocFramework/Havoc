package rpc

import (
    "bufio"
    "encoding/json"
    "net"
    "strconv"

    "Havoc/pkg/colors"
    "Havoc/pkg/logger"
)

func NewServer(port int) (*Server, error) {
    var (
        server = new(Server)
    )

    server.IPCPort = port
    return server, nil
}

func (s *Server) StartRPC() error {
    var (
        err        error
        ServerAddr = "localhost:" + strconv.Itoa(s.IPCPort)
    )

    s.Listener, err = net.Listen("tcp", ServerAddr)
    if err != nil {
        return err
    }

    logger.Debug("Started RPC server: " + colors.BlueUnderline(ServerAddr))

    go s.serverRoutine()
    return nil
}

func (s *Server) serverRoutine() {
    for {
        clientConnection, err := s.Listener.Accept()
        if err != nil {
            logger.Error("Couldn't accept client connection: " + err.Error())
        }

        logger.Debug("New Client: ", &clientConnection)
        s.Clients = append(s.Clients, clientConnection)
        go s.handleClientRPC(clientConnection)
    }
}

func (s *Server) handleClientRPC(client net.Conn) {
    var reader = bufio.NewReader(client)

    defer func(client net.Conn) {
        err := client.Close()
        if err != nil {
            logger.Error("Couldn't close client: ", &client)
        } else {
            logger.Debug("Closed client: ", &client)
        }
    }(client)

    for {
        var jsonStruct, _, _ = reader.ReadLine()
        if len(jsonStruct) > 0 {
            s.ReceiveData(jsonStruct)
        }
    }
}

func (s *Server) ReceiveData(jsonStruct []byte) {
    var EventData Data
    err := json.Unmarshal(jsonStruct, &EventData)
    if err != nil {
        logger.Error("Unmarshal error: " + colors.Red(err.Error()))
    }
    s.DispatchEvent(EventData)
}

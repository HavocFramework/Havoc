package rpc

import (
    "encoding/json"
    "net"
    "strconv"

    "github.com/Cracked5pider/Havoc/teamserver/pkg/logger"
)

func NewClient(port int) (*Client, error) {
    var (
    	client      = new(Client)
    )
    client.IPCPort = port
    return client, nil
}

func (c *Client) Connect() error {
    var (
    	servAddr    = "localhost:"+strconv.Itoa(c.IPCPort)
        err         error
    )
    tcpAddr, err := net.ResolveTCPAddr("tcp", servAddr)
    if err != nil {
        return err
    }

    c.Conn, err = net.DialTCP("tcp", nil, tcpAddr)
    if err != nil {
        return err
    }
    return nil
}

func (c *Client) SendEventData(EventData Data) {
    jsonStruct, err := json.Marshal(EventData)
    if err != nil {
        logger.Error("Marshal err: " + err.Error())
    }
    _, err = c.Conn.Write(jsonStruct)
    if err != nil {
        logger.Error("Couldn't Send data: " + err.Error())
    }
}
package handlers
/*
import (
    "fmt"
    "log"
    "strconv"

    "github.com/Cracked5pider/Havoc/teamserver/pkg/logger"
    "github.com/miekg/dns"
)

var records = map[string]string{
    "test.service.": "192.168.0.148",
}

func parseQuery(m *dns.Msg) {
    for _, q := range m.Question {
        switch q.Qtype {
        case dns.TypeA:
            logger.Info(fmt.Sprintf("Query for %s\n", q.Name))
            ip := records[q.Name]
            if ip != "" {
                logger.Info(fmt.Sprintf("%s A %s", q.Name, ip))
                rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
                if err == nil {
                    m.Answer = append(m.Answer, rr)
                }
            }
        }
    }
}

// TODO: finish this
func StartListenerDNS(Host string, Port string, Domains []string) *DNS {

    // attach request handler func
    dns.HandleFunc("service.", HandleRequest)

    // start server
    port := 5354
    server := &dns.Server{Addr: ":" + strconv.Itoa(port), Net: "udp"}
    logger.Info(fmt.Sprintf("Starting at %d\n", port))
    err := server.ListenAndServe()
    defer server.Shutdown()
    if err != nil {
        log.Fatalf("Failed to start server: %s\n ", err.Error())
    }

    return nil
}

func HandleRequest(writer dns.ResponseWriter, req *dns.Msg) {
    m := new(dns.Msg)
    m.SetReply(req)
    m.Compress = false

    switch req.Opcode {
    case dns.OpcodeQuery:
        parseQuery(m)
    }

    writer.WriteMsg(m)
}*/
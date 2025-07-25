package server

import "C"
import (
	"Havoc/pkg/agent"
	"Havoc/pkg/common/certs"
	"Havoc/pkg/db"
	"Havoc/pkg/service"
	"Havoc/pkg/webhook"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/sha3"

	"Havoc/pkg/colors"
	"Havoc/pkg/common"
	"Havoc/pkg/events"
	"Havoc/pkg/handlers"
	"Havoc/pkg/logger"
	"Havoc/pkg/packager"
	"Havoc/pkg/profile"
	"Havoc/pkg/utils"
)

func NewTeamserver(DatabasePath string) *Teamserver {
	if d, err := db.DatabaseNew(DatabasePath); err != nil {
		logger.Error("Failed to create a new db: " + err.Error())
		return nil
	} else {
		return &Teamserver{
			DB: d,
		}
	}
}

func (t *Teamserver) SetServerFlags(flags TeamserverFlags) {
	t.Flags = flags
}

func (t *Teamserver) Start() {
	logger.Debug("Starting teamserver...")
	var (
		ServerFinished      chan bool
		TeamserverWs        string
		TeamserverPath, err = os.Getwd()
		ListenerCount       int
		KillDate            int64
	)

	if err != nil {
		logger.Error("Couldn't get the current directory: " + err.Error())
		return
	}

	if t.Flags.Server.Host == "" {
		t.Flags.Server.Host = t.Profile.ServerHost()
	}

	if t.Flags.Server.Port == "" {
		t.Flags.Server.Port = strconv.Itoa(t.Profile.ServerPort())
	}

	gin.SetMode(gin.ReleaseMode)
	t.Server.Engine = gin.New()

	t.Server.Engine.GET("/", func(context *gin.Context) {
		context.Redirect(http.StatusMovedPermanently, "home/")
	})

	// Catch me if you can
	t.Server.Engine.GET("/havoc/", func(context *gin.Context) {

		var (
			upgrade   websocket.Upgrader
			WebSocket *websocket.Conn
			ClientID  = utils.GenerateID(6)
		)

		if WebSocket, err = upgrade.Upgrade(context.Writer, context.Request, nil); err != nil {
			logger.Error("Failed upgrading request: " + err.Error())
			return
		}

		t.Clients.Store(ClientID,
			&Client{
				Username:      "",
				GlobalIP:      WebSocket.RemoteAddr().String(),
				Connection:    WebSocket,
				ClientVersion: "",
				Packager:      packager.NewPackager(),
				Authenticated: false,
			})

		// Handle connections in a new goroutine.
		go t.handleRequest(ClientID)
	})

	// TODO: pass this as a profile/command line flag
	t.Server.Engine.Static("/home", "./bin/static")

	t.Server.Engine.POST("/:endpoint", func(context *gin.Context) {
		var endpoint = context.Request.RequestURI[1:]

		if len(t.Endpoints) > 0 {
			for i := range t.Endpoints {
				if t.Endpoints[i].Endpoint == endpoint {
					t.Endpoints[i].Function(context)
				}
			}
		}
	})

	// start the teamserver websocket connection
	go func(Host, Port string) {
		var (
			certPath = TeamserverPath + "/data/server.cert"
			keyPath  = TeamserverPath + "/data/server.key"

			Cert []byte
			Key  []byte
		)

		Cert, Key, err = certs.HTTPSGenerateRSACertificate(Host)
		if err != nil {
			logger.Error("Failed to generate server certificates: " + err.Error())
			os.Exit(0)
		}

		err = os.WriteFile(certPath, Cert, 0644)
		if err != nil {
			logger.Error("Couldn't save server cert file: " + err.Error())
			os.Exit(0)
		}

		err = os.WriteFile(keyPath, Key, 0644)
		if err != nil {
			logger.Error("Couldn't save server cert file: " + err.Error())
			os.Exit(0)
		}

		// start the teamserver
		if err = t.Server.Engine.RunTLS(Host+":"+Port, certPath, keyPath); err != nil {
			logger.Error("Failed to start websocket: " + err.Error())
		}

		ServerFinished <- true

		os.Exit(0)
	}(t.Flags.Server.Host, t.Flags.Server.Port)

	t.WebHooks = webhook.NewWebHook()
	t.Listeners = []*Listener{}

	TeamserverWs = "wss://" + t.Flags.Server.Host + ":" + t.Flags.Server.Port

	logger.Info("Starting Teamserver on " + colors.BlueUnderline(TeamserverWs))

	/* if we specified a webhook then lets use it. */
	if t.Profile.Config.WebHook != nil {
		if t.Profile.Config.WebHook.Discord != nil {
			var (
				AvatarUrl string
				UserName  string
			)

			if len(t.Profile.Config.WebHook.Discord.AvatarUrl) > 0 {
				AvatarUrl = t.Profile.Config.WebHook.Discord.AvatarUrl
			}

			if len(t.Profile.Config.WebHook.Discord.UserName) > 0 {
				UserName = t.Profile.Config.WebHook.Discord.UserName
			}

			if len(t.Profile.Config.WebHook.Discord.WebHook) > 0 {
				t.WebHooks.SetDiscord(AvatarUrl, UserName, t.Profile.Config.WebHook.Discord.WebHook)
			}
		}

		if t.Profile.Config.WebHook.Mattermost != nil {
			var (
				AvatarUrl string
				UserName  string
			)
			if len(t.Profile.Config.WebHook.Mattermost.AvatarUrl) > 0 {
				AvatarUrl = t.Profile.Config.WebHook.Mattermost.AvatarUrl
			}
			if len(t.Profile.Config.WebHook.Mattermost.UserName) > 0 {
				UserName = t.Profile.Config.WebHook.Mattermost.UserName
			}

			if len(t.Profile.Config.WebHook.Mattermost.WebHook) > 0 {
				t.WebHooks.SetMattermost(AvatarUrl, UserName, t.Profile.Config.WebHook.Mattermost.WebHook)
			}
		}
	}

	// start teamserver service
	if t.Profile.Config.Service != nil {

		// 3rd Party Agent Support Enabled
		t.Service = service.NewService(t.Server.Engine)
		t.Service.Teamserver = t
		t.Service.Data.ServerAgents = &t.Agents
		t.Service.Config = *t.Profile.Config.Service

		if len(t.Service.Config.Endpoint) > 0 {
			t.Service.Start()
			logger.Info(fmt.Sprintf("%v starting service handle on %v", "["+colors.BoldWhite("SERVICE")+"]", colors.BlueUnderline(TeamserverWs+"/"+t.Service.Config.Endpoint)))
		} else {
			logger.Error("Teamserver service error: Endpoint not specified")
		}
	}

	/* now load up our db or start a new one if none exist */
	DBPath := t.DB.Path()
	if t.DB, err = db.DatabaseNew(TeamserverPath + "/" + DBPath); err != nil {
		logger.SetStdOut(os.Stderr)
		logger.Error("Failed to create or open a database: " + err.Error())
		return
	}

	if t.DB.Existed() {
		logger.Info("Opens existing database: " + colors.Blue(DBPath))
	} else {
		logger.Info("Creates new database: " + colors.Blue(DBPath))
	}

	ListenerCount = t.DB.ListenerCount()

	/* start listeners from the specified yaotl profile */
	if t.Profile.Config.Listener != nil {

		/* Start all HTTP/s listeners */
		for _, listener := range t.Profile.Config.Listener.ListenerHTTP {
			if listener.KillDate != "" {
				t, err := time.Parse("2006-01-02 15:04:05", listener.KillDate)
				if err != nil {
					logger.Error("Failed to parse the kill date: " + err.Error())
					return
				}
				KillDate = common.EpochTimeToSystemTime(t.Unix())
			} else {
				KillDate = 0
			}

			var HandlerData = handlers.HTTPConfig{
				Name:         listener.Name,
				KillDate:     KillDate,
				WorkingHours: listener.WorkingHours,
				Hosts:        listener.Hosts,
				HostBind:     listener.HostBind,
				Methode:      listener.Methode,
				HostRotation: listener.HostRotation,
				BehindRedir:  t.Profile.Config.Demon.TrustXForwardedFor,
				PortBind:     strconv.Itoa(listener.PortBind),
				PortConn:     strconv.Itoa(listener.PortConn),
				UserAgent:    listener.UserAgent,
				Headers:      listener.Headers,
				Uris:         listener.Uris,
				Secure:       listener.Secure,
				HostHeader:   listener.HostHeader,
				Proxy:        handlers.ProxyConfig{},
			}

			// Set proxy settings
			if listener.Proxy != nil {
				if strings.HasPrefix(listener.Proxy.Host, "http://") || strings.HasPrefix(listener.Proxy.Host, "https://") {
					logger.Error("Proxy host should not start with scheme")
					return
				}

				HandlerData.Proxy = handlers.ProxyConfig{
					Enabled:  len(listener.Proxy.Host) > 0,
					Type:     listener.Proxy.Type,
					Host:     listener.Proxy.Host,
					Port:     strconv.Itoa(listener.Proxy.Port),
					Username: listener.Proxy.User,
					Password: listener.Proxy.Pass,
				}
			}

			if listener.Cert != nil {
				var Found = true

				if _, err = os.Stat(listener.Cert.Cert); !os.IsNotExist(err) {
					HandlerData.Cert.Cert = listener.Cert.Cert
				} else {
					Found = false
				}

				if _, err = os.Stat(listener.Cert.Key); !os.IsNotExist(err) {
					HandlerData.Cert.Key = listener.Cert.Key
				} else {
					Found = false
				}

				if !Found {
					logger.Error("Failed to find Cert/Key Path for listener '" + listener.Name + "'. Using randomly generated certs")
				}
			}

			if listener.Response != nil {
				HandlerData.Response.Headers = listener.Response.Headers
			}

			if err := t.ListenerStart(handlers.LISTENER_HTTP, HandlerData); err != nil {
				logger.Error("Failed to start listener from profile: " + err.Error())
				return
			}
		}

		/* Start all SMB listeners */
		for _, listener := range t.Profile.Config.Listener.ListenerSMB {
			if listener.KillDate != "" {
				t, err := time.Parse("2006-01-02 15:04:05", listener.KillDate)
				if err != nil {
					logger.Error("Failed to parse the kill date: " + err.Error())
					return
				}
				KillDate = common.EpochTimeToSystemTime(t.Unix())
			} else {
				KillDate = 0
			}

			var HandlerData = handlers.SMBConfig{
				Name:         listener.Name,
				PipeName:     listener.PipeName,
				KillDate:     KillDate,
				WorkingHours: listener.WorkingHours,
			}

			if err := t.ListenerStart(handlers.LISTENER_PIVOT_SMB, HandlerData); err != nil {
				logger.Error("Failed to start listener from profile: " + err.Error())
				return
			}
		}

		/* Start all ExternalC2 listeners */
		for _, listener := range t.Profile.Config.Listener.ListenerExternal {
			var HandlerData = handlers.ExternalConfig{
				Name:     listener.Name,
				Endpoint: listener.Endpoint,
			}

			if err := t.ListenerStart(handlers.LISTENER_EXTERNAL, HandlerData); err != nil {
				logger.Error("Failed to start listener from profile: " + err.Error())
				return
			}
		}

	}

	if ListenerCount > 0 {
		var TotalCount = 0
		if DbName := t.DB.ListenerNames(); len(DbName) > 0 {
			TotalCount = ListenerCount
			for _, name := range DbName {
				for _, listener := range t.Listeners {
					if listener.Name == name {
						TotalCount--
						break
					}
				}
			}
		}

		if TotalCount > 0 {
			logger.Info(fmt.Sprintf("Starting %v listeners from last session", colors.Green(TotalCount)))
		}
	}

	for _, listener := range t.DB.ListenerAll() {

		switch listener["Protocol"] {

		case handlers.AGENT_HTTP, handlers.AGENT_HTTPS:

			var (
				Data        = make(map[string]any)
				HandlerData = handlers.HTTPConfig{
					Name: listener["Name"],
				}
			)

			err = json.Unmarshal([]byte(listener["Config"]), &Data)
			if err != nil {
				logger.Error("Failed to unmarshal json bytes to map: " + err.Error())
				continue
			}

			/* set config of http listener */
			HandlerData.Hosts = strings.Split(Data["Hosts"].(string), ", ")
			HandlerData.HostBind = Data["HostBind"].(string)
			HandlerData.HostRotation = Data["HostRotation"].(string)
			HandlerData.PortBind = Data["PortBind"].(string)
			HandlerData.UserAgent = Data["UserAgent"].(string)
			HandlerData.Headers = strings.Split(Data["Headers"].(string), "\r\n")
			HandlerData.Uris = strings.Split(Data["Uris"].(string), ", ")
			HandlerData.BehindRedir = t.Profile.Config.Demon.TrustXForwardedFor

			HandlerData.Secure = false
			if Data["Secure"].(string) == "true" {
				HandlerData.Secure = true
			}

			if Data["Response Headers"] != nil {

				switch Data["Response Headers"].(type) {

				case string:
					HandlerData.Response.Headers = strings.Split(Data["Response Headers"].(string), "\r\n")
					break

				default:
					for _, s := range Data["Response Headers"].([]interface{}) {
						HandlerData.Response.Headers = append(HandlerData.Response.Headers, s.(string))
					}

				}
			}

			/* also ignore if we already have a listener running */
			if err := t.ListenerStart(handlers.LISTENER_HTTP, HandlerData); err != nil && err.Error() != "listener already exists" {
				logger.SetStdOut(os.Stderr)
				logger.Error("Failed to start listener from db: " + err.Error())
				return
			}

			break

		case handlers.AGENT_EXTERNAL:

			var (
				Data        = make(map[string]any)
				HandlerData = handlers.ExternalConfig{
					Name: listener["Name"],
				}
			)

			err := json.Unmarshal([]byte(listener["Config"]), &Data)
			if err != nil {
				logger.Debug("Failed to unmarshal json bytes to map: " + err.Error())
				continue
			}

			HandlerData.Endpoint = Data["Endpoint"].(string)

			if err := t.ListenerStart(handlers.LISTENER_EXTERNAL, HandlerData); err != nil && err.Error() != "listener already exists" {
				logger.SetStdOut(os.Stderr)
				logger.Error("Failed to start listener from db: " + err.Error())
				return
			}

			break

		case handlers.AGENT_PIVOT_SMB:

			var (
				Data        = make(map[string]any)
				HandlerData = handlers.SMBConfig{
					Name: listener["Name"],
				}
			)

			err := json.Unmarshal([]byte(listener["Config"]), &Data)
			if err != nil {
				logger.Debug("Failed to unmarshal json bytes to map: " + err.Error())
				continue
			}

			HandlerData.PipeName = Data["PipeName"].(string)

			if err := t.ListenerStart(handlers.LISTENER_PIVOT_SMB, HandlerData); err != nil && err.Error() != "listener already exists" {
				logger.SetStdOut(os.Stderr)
				logger.Error("Failed to start listener from db: " + err.Error())
				return
			}

			break

		}

	}

	// load all existing Agents from the DB
	Agents := t.DB.AgentAll()
	for _, Agent := range Agents {
		t.AgentAdd(Agent)
	}

	for _, Agent := range Agents {
		// check if the agent has a parent
		parentID, err := t.ParentOf(Agent)
		if err == nil {
			Agent.Pivots.Parent = t.AgentInstance(parentID)
		}
		// check if the agent has any links
		AgentsIDs := t.LinksOf(Agent)
		for _, AgentID := range AgentsIDs {
			Agent.Pivots.Links = append(Agent.Pivots.Links, t.AgentInstance(AgentID))
		}
	}

	// notify the clients
	for _, Agent := range Agents {
		t.AgentSendNotify(Agent)
	}

	if len(Agents) > 0 {
		logger.Info(fmt.Sprintf("Restored %v agents from last session", colors.Green(len(Agents))))
	}

	t.EventAppend(events.SendProfile(t.Profile))

	// This should hold the Teamserver as long as the WebSocket Server is running
	logger.Debug("Wait til the server shutdown")

	<-ServerFinished
}

func (t *Teamserver) handleRequest(id string) {
	value, isok := t.Clients.Load(id)

	if !isok {
		return
	}

	client := value.(*Client)
	_, NewClient, err := client.Connection.ReadMessage()

	if err != nil {
		if err != io.EOF {
			logger.Error("Error reading 2:", err.Error())
			if strings.Contains(err.Error(), "connection reset by peer") {
				err := client.Connection.Close()
				if err != nil {
					logger.Error("Error while closing Client connection: " + err.Error())
				}
			}
		}
		t.Clients.Delete(id)
		return
	}

	pk := client.Packager.CreatePackage(string(NewClient))

	if t.Profile != nil {
		var found = false
		for _, UserNames := range t.Profile.ListOfUsernames() {
			if UserNames == pk.Head.User {
				found = true
			}
		}
		if !found {
			err := t.SendEvent(id, events.UserDoNotExists())
			if err != nil {
				logger.Error("Error while sending package to " + colors.Red(id) + "")
			}
			t.RemoveClient(id)
			return
		}
	}

	isExist := false
	t.Clients.Range(func(key, value any) bool {
		if client.Username == pk.Head.User {
			err := t.SendEvent(id, events.UserAlreadyExits())
			if err != nil {
				logger.Error("couldn't send event to client "+colors.Yellow(id)+":", err)
			}
			t.RemoveClient(id)
			isExist = true
			return false
		}
		return true
	})
	if isExist {
		return
	}
	if !t.ClientAuthenticate(pk) {
		logger.Error("Client [User: " + pk.Body.Info["User"].(string) + "] failed to Authenticate! (" + colors.Red(client.GlobalIP) + ")")
		err := t.SendEvent(id, events.Authenticated(false))
		if err != nil {
			logger.Error("client (" + colors.Red(id) + ") error while sending authenticate message: " + colors.Red(err))
		}
		err = client.Connection.Close()
		if err != nil {
			logger.Error("Failed to close client (" + id + ") socket")
		}
		return
	} else {

		logger.Good("User <" + colors.Blue(pk.Body.Info["User"].(string)) + "> " + colors.Green("Authenticated"))

		client.Authenticated = true
		client.ClientID = id

		err := t.SendEvent(id, events.Authenticated(true))
		if err != nil {
			logger.Error("client (" + colors.Red(id) + ") error while sending authenticate message:" + colors.Red(err))
		}
	}

	client.Username = pk.Body.Info["User"].(string)
	packageNewUser := events.ChatLog.NewUserConnected(client.Username)
	t.EventAppend(packageNewUser)
	t.EventBroadcast(id, packageNewUser)

	t.SendAllPackagesToNewClient(id)

	for {
		value, isok := t.Clients.Load(id)
		if !isok {
			return
		}
		client = value.(*Client)
		_, EventPackage, err := client.Connection.ReadMessage()

		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseAbnormalClosure) {
				logger.Warn("User <" + colors.Blue(client.Username) + "> " + colors.Red("Disconnected"))

				t.EventAppend(events.ChatLog.UserDisconnected(client.Username))
				t.RemoveClient(id)

				return
			} else {
				logger.Error("Error reading :", err.Error())
			}

			err := client.Connection.Close()
			if err != nil {
				logger.Error("Socket Error:", err.Error())
			}

			t.EventAppend(events.ChatLog.UserDisconnected(client.Username))
			t.RemoveClient(id)

			return
		}

		pk := client.Packager.CreatePackage(string(EventPackage))
		pk.Head.Time = time.Now().Format("02/01/2006 15:04:05")

		t.EventAppend(pk)
		t.DispatchEvent(pk)
	}
}

func (t *Teamserver) SetProfile(path string) {
	t.Profile = profile.NewProfile()
	logger.LoggerInstance.STDERR = os.Stderr
	err := t.Profile.SetProfile(path, t.Flags.Server.Default)
	if err != nil {
		logger.SetStdOut(os.Stderr)
		logger.Error("Profile error:", colors.Red(err))
		os.Exit(1)
	}
}

func (t *Teamserver) ClientAuthenticate(pk packager.Package) bool {
	if pk.Head.Event == packager.Type.InitConnection.Type {
		if pk.Body.SubEvent == packager.Type.InitConnection.OAuthRequest {
			if t.Profile != nil {
				if t.Profile.Config.Operators != nil {
					var (
						UserPassword string
						UserName     string
						PassHash     = sha3.New256()
						UserFound    = false
					)

					// search for operator
					for _, User := range t.Profile.Config.Operators.Users {
						if User.Name == pk.Head.User {
							UserName = User.Name
							UserFound = true

							PassHash.Write([]byte(User.Password))
							UserPassword = hex.EncodeToString(PassHash.Sum(nil))

							logger.Debug("Found User: " + User.Name)
						}
					}

					// check if the operator was even found
					if UserFound {
						if pk.Body.Info["Password"].(string) == UserPassword {
							logger.Debug("User " + colors.Red(UserName) + " is authenticated")
							return true
						}
					} else {
						logger.Debug("User not found")
					}

					logger.Debug("User not authenticated")
				}

				return false
			} else {
				return false
			}
		} else {
			logger.Error("Wrong SubEvent :: " + strconv.Itoa(pk.Body.SubEvent))
		}
	} else {
		logger.Error("Not a Authenticate request")
	}

	logger.Error("Client failed to authenticate with password hash :: " + pk.Body.Info["Password"].(string))
	return false
}

func (t *Teamserver) EventBroadcast(ExceptClient string, pk packager.Package) {

	// some sanity check
	if pk.Head.Event == 0 {
		return
	}

	t.Clients.Range(func(key, value any) bool {
		ClientID := key.(string)
		if ExceptClient != ClientID {
			err := t.SendEvent(ClientID, pk)
			if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
				logger.Error("SendEvent error: ", colors.Red(err))
			}
		}
		return true
	})
}

func (t *Teamserver) EventNewDemon(DemonAgent *agent.Agent) packager.Package {
	return events.Demons.NewDemon(DemonAgent)
}

func (t *Teamserver) EventAgentMark(AgentID, Mark string) {
	var pk = events.Demons.MarkAs(AgentID, Mark)

	t.EventAppend(pk)
	t.EventBroadcast("", pk)
}

func (t *Teamserver) EventListenerError(ListenerName string, Error error) {
	var pk = events.Listener.ListenerError("", ListenerName, Error)

	t.EventAppend(pk)
	t.EventBroadcast("", pk)

	// also remove the listener from the init packages.
	for EventID := range t.EventsList {
		if t.EventsList[EventID].Head.Event == packager.Type.Listener.Type {
			if t.EventsList[EventID].Body.SubEvent == packager.Type.Listener.Add {
				if name, ok := t.EventsList[EventID].Body.Info["Name"]; ok {
					if name == ListenerName {
						t.EventsList[EventID].Body.Info["Status"] = "Offline"
						t.EventsList[EventID].Body.Info["Error"] = Error.Error()
					}
				}
			}
		}
	}
}

func (t *Teamserver) SendEvent(id string, pk packager.Package) error {
	var (
		buffer bytes.Buffer
		err    error
	)

	err = json.NewEncoder(&buffer).Encode(pk)
	if err != nil {
		return err
	}

	value, isOk := t.Clients.Load(id)
	if isOk {
		client := value.(*Client)
		client.Mutex.Lock()

		err = client.Connection.WriteMessage(websocket.BinaryMessage, buffer.Bytes())
		if err != nil {
			// TODO: comment this line out as it seems to crash the server
			//t.Clients[id].Mutex.Unlock()
			return err
		}

		client.Mutex.Unlock()

	} else {
		return errors.New(fmt.Sprintf("client (%v) doesn't exist anymore", colors.Red(id)))
	}

	return nil
}

func (t *Teamserver) RemoveClient(ClientID string) {

	value, isOk := t.Clients.Load(ClientID)

	if isOk {
		client := value.(*Client)
		var (
			userDisconnected = client.Username
			Authenticated    = client.Authenticated
		)

		if Authenticated {
			t.EventBroadcast(ClientID, events.ChatLog.UserDisconnected(userDisconnected))
			for UserID := range t.Users {
				if userDisconnected == t.Users[UserID].Name {
					t.Users[UserID].Online = false
				}
			}
		}

		t.Clients.Delete(ClientID)
	}
}

func (t *Teamserver) EventAppend(event packager.Package) []packager.Package {

	// some sanity check
	if event.Head.Event == 0 {
		return t.EventsList
	}

	if event.Head.OneTime != "true" {
		t.EventsList = append(t.EventsList, event)
		return append(t.EventsList, event)
	}

	return nil
}

func (t *Teamserver) EventRemove(EventID int) []packager.Package {
	t.EventsList = append(t.EventsList[:EventID], t.EventsList[EventID+1:]...)

	return append(t.EventsList[:EventID], t.EventsList[EventID+1:]...)
}

func (t *Teamserver) SendAllPackagesToNewClient(ClientID string) {
	for _, Package := range t.EventsList {
		err := t.SendEvent(ClientID, Package)
		if err != nil {
			logger.Error("error while sending info to client("+ClientID+"): ", err)
			return
		}
	}

	// send all the agents that are alive right now to the new client
	for _, demon := range t.Agents.Agents {
		if demon.Active == false {
			continue
		}

		pk := t.EventNewDemon(demon)
		err := t.SendEvent(ClientID, pk)
		if err != nil {
			logger.Error("error while sending info to client("+ClientID+"): ", err)
			return
		}
	}
}

func (t *Teamserver) FindSystemPackages() bool {
	var err error

	if t.Profile.Config.Server.Build != nil {

		if len(t.Profile.Config.Server.Build.Compiler64) > 0 {
			if _, err := os.Stat(t.Profile.Config.Server.Build.Compiler64); os.IsNotExist(err) {
				logger.SetStdOut(os.Stderr)
				logger.Error("Compiler x64 path doesn't exist: " + t.Profile.Config.Server.Build.Compiler64)
				return false
			}

			t.Settings.Compiler64 = t.Profile.Config.Server.Build.Compiler64
		} else {
			t.Settings.Compiler64, err = exec.LookPath("x86_64-w64-mingw32-gcc")
			if err != nil {
				logger.SetStdOut(os.Stderr)
				logger.Error("Couldn't find x64 mingw compiler: " + err.Error())
				return false
			}
		}

		if len(t.Profile.Config.Server.Build.Compiler86) > 0 {
			if _, err := os.Stat(t.Profile.Config.Server.Build.Compiler86); os.IsNotExist(err) {
				logger.SetStdOut(os.Stderr)
				logger.Error("Compiler x86 path doesn't exist: " + t.Profile.Config.Server.Build.Compiler86)
				return false
			}

			t.Settings.Compiler32 = t.Profile.Config.Server.Build.Compiler86
		} else {
			t.Settings.Compiler32, err = exec.LookPath("i686-w64-mingw32-gcc")
			if err != nil {
				logger.SetStdOut(os.Stderr)
				logger.Error("Couldn't find x86 mingw compiler: " + err.Error())
				return false
			}
		}

		if len(t.Profile.Config.Server.Build.Nasm) > 0 {
			if _, err := os.Stat(t.Profile.Config.Server.Build.Nasm); os.IsNotExist(err) {
				logger.SetStdOut(os.Stderr)
				logger.Error("Nasm path doesn't exist: " + t.Profile.Config.Server.Build.Nasm)
				return false
			}

			t.Settings.Nasm = t.Profile.Config.Server.Build.Nasm
		} else {
			t.Settings.Nasm, err = exec.LookPath("nasm")
			if err != nil {
				logger.Error("Couldn't find nasm: " + err.Error())
				return false
			}
		}

	} else {
		t.Settings.Compiler64, err = exec.LookPath("x86_64-w64-mingw32-gcc")
		if err != nil {
			logger.SetStdOut(os.Stderr)
			logger.Error("Couldn't find x64 mingw compiler: " + err.Error())
			return false
		}

		t.Settings.Compiler32, err = exec.LookPath("i686-w64-mingw32-gcc")
		if err != nil {
			logger.SetStdOut(os.Stderr)
			logger.Error("Couldn't find x86 mingw compiler: " + err.Error())
			return false
		}

		t.Settings.Nasm, err = exec.LookPath("nasm")
		if err != nil {
			logger.SetStdOut(os.Stderr)
			logger.Error("Couldn't find nasm: " + err.Error())
			return false
		}
	}

	logger.Info(fmt.Sprintf(
		"Build: \n"+
			" - Compiler x64 : %v\n"+
			" - Compiler x86 : %v\n"+
			" - Nasm         : %v",
		colors.Blue(t.Settings.Compiler64),
		colors.Blue(t.Settings.Compiler32),
		colors.Blue(t.Settings.Nasm),
	))

	return true
}

func (t *Teamserver) EndpointAdd(endpoint *Endpoint) bool {
	for _, e := range t.Endpoints {
		if e.Endpoint == endpoint.Endpoint {
			return false
		}
	}

	t.Endpoints = append(t.Endpoints, endpoint)

	return true
}

func (t *Teamserver) EndpointRemove(endpoint string) []*Endpoint {
	for i := range t.Endpoints {
		if t.Endpoints[i].Endpoint == endpoint {
			t.Endpoints = append(t.Endpoints[:i], t.Endpoints[i+1:]...)
			return t.Endpoints
		}
	}

	return t.Endpoints
}

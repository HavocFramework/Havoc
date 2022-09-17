package teamserver

import "C"
import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"Havoc/pkg/service"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/sha3"

	"Havoc/pkg/colors"
	"Havoc/pkg/events"
	"Havoc/pkg/handlers"
	"Havoc/pkg/logger"
	"Havoc/pkg/packager"
	"Havoc/pkg/profile"
	"Havoc/pkg/utils"
)

// maybe move this to cmd

var HavocTeamserver *Teamserver

func NewTeamserver() *Teamserver {
	return new(Teamserver)
}

func (t *Teamserver) SetServerFlags(flags TeamserverFlags) {
	t.Flags = flags
}

func (t *Teamserver) Start() {
	logger.Debug("Starting teamserver...")
	var (
		ServerFinished chan bool
		TeamserverWs   string
	)

	if t.Flags.Server.Host == "" {
		t.Flags.Server.Host = t.Profile.ServerHost()
	}

	if t.Flags.Server.Port == "" {
		t.Flags.Server.Port = strconv.Itoa(t.Profile.ServerPort())
	}

	// ------- WebSocket Server implementation -------
	gin.SetMode(gin.ReleaseMode)
	t.Server.Engine = gin.New()

	t.Server.Engine.GET("/", func(context *gin.Context) {
		context.Redirect(http.StatusMovedPermanently, "home/")
	})

	// Catch me if you can
	t.Server.Engine.GET("/havoc/", func(context *gin.Context) {
		upgrade := websocket.Upgrader{}
		WebSocket, err := upgrade.Upgrade(context.Writer, context.Request, nil)
		if err != nil {
			logger.Error("Failed upgrading request")
			return
		}

		var ClientID = utils.GenerateID(6)
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}

		t.Clients[ClientID] = &Client{
			Username:      "",
			GlobalIP:      WebSocket.RemoteAddr().String(),
			Connection:    WebSocket,
			ClientVersion: "",
			Packager:      packager.NewPackager(),
			Authenticated: false,
		}

		// Handle connections in a new goroutine.
		go t.handleRequest(ClientID)
	})

	// TODO: pass this as a profile/command line flag
	t.Server.Engine.Static("/home", "./bin/static")

	go func(Server string) {
		err := t.Server.Engine.Run(Server)
		if err != nil {
			logger.Error("Failed to start websocket: " + err.Error())
		}
		ServerFinished <- true
	}(t.Flags.Server.Host + ":" + t.Flags.Server.Port)

	// -------
	t.Service = service.NewService(t.Server.Engine)
	t.Service.Events = t
	t.Service.TeamAgents = &t.Agents
	t.Clients = make(map[string]*Client)
	t.Listeners = []*Listener{}
	TeamserverWs = "ws://" + t.Flags.Server.Host + ":" + t.Flags.Server.Port
	t.Service.Data.ServerAgents = &t.Agents

	logger.Info("Starting Teamserver on " + colors.BlueUnderline(TeamserverWs))

	// start teamserver service
	if t.Profile.Config.Service != nil {
		t.Service.Config = *t.Profile.Config.Service

		if len(t.Service.Config.Endpoint) > 0 {
			t.Service.Start()
			logger.Info("Starting Teamserver service handler on " + colors.BlueUnderline(TeamserverWs+"/"+t.Service.Config.Endpoint))
		} else {
			logger.Error("Teamserver service error: Endpoint not specified")
		}
	}

	// start all listeners
	if t.Profile.Config.Listener != nil {

		// Start all HTTP/s listeners
		for _, listener := range t.Profile.Config.Listener.ListenerHTTP {
			var HandlerData = handlers.HTTPConfig{
				Name:      listener.Name,
				Hosts:     listener.Host,
				Port:      strconv.Itoa(listener.Port),
				UserAgent: listener.UserAgent,
				Headers:   listener.Headers,
				Uris:      listener.Uris,
				Secure:    listener.Secure,
			}

			if listener.Response != nil {
				HandlerData.Response.Headers = listener.Response.Headers
			}

			if err := t.ListenerStart(handlers.LISTENER_HTTP, HandlerData); err != nil {
				logger.Error("Failed to start listener: " + err.Error())
				return
			}
		}

		// Start all SMB listeners
		for _, listener := range t.Profile.Config.Listener.ListenerSMB {
			var HandlerData = handlers.SMBConfig{
				Name:     listener.Name,
				PipeName: listener.PipeName,
			}

			if err := t.ListenerStart(handlers.LISTENER_PIVOT_SMB, HandlerData); err != nil {
				logger.Error("Failed to start listener: " + err.Error())
				return
			}
		}

		// Start all ExternalC2 listeners
		for _, listener := range t.Profile.Config.Listener.ListenerExternal {
			var HandlerData = handlers.ExternalConfig{
				Name:     listener.Name,
				Endpoint: listener.Endpoint,
			}

			if err := t.ListenerStart(handlers.LISTENER_EXTERNAL, HandlerData); err != nil {
				logger.Error("Failed to start listener: " + err.Error())
				return
			}
		}

	}

	t.EventAppend(events.SendDemonProfile(t.Profile.Config.Demon))

	// This should hold the Teamserver as long as the WebSocket Server is running
	logger.Debug("Wait til the server shutdown")

	<-ServerFinished
}

func (t *Teamserver) handleRequest(id string) {
	_, NewClient, err := t.Clients[id].Connection.ReadMessage()

	if err != nil {
		if err != io.EOF {
			logger.Error("Error reading 2:", err.Error())
			if strings.Contains(err.Error(), "connection reset by peer") {
				err := t.Clients[id].Connection.Close()
				if err != nil {
					logger.Error("Error while closing Client connection: " + err.Error())
				}
			}
		}
		return
	}

	pk := t.Clients[id].Packager.CreatePackage(string(NewClient))

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
				return
			}
			t.RemoveClient(id)
		}
	}

	for i := range t.Clients {
		if t.Clients[i].Username == pk.Head.User {
			err := t.SendEvent(id, events.UserAlreadyExits())
			if err != nil {
				logger.Error("couldn't send event to client "+colors.Yellow(id)+":", err)
			}
			t.RemoveClient(id)
		}
	}

	if !t.ClientAuthenticate(pk) {
		if t.Clients[id] == nil {
			return
		}
		logger.Error("Client (" + id + ") User (" + pk.Body.Info["User"].(string) + ") failed to Authenticate! (" + colors.Red(t.Clients[id].GlobalIP) + ")")
		err := t.SendEvent(id, events.Authenticated(false))
		if err != nil {
			logger.Error("client (" + colors.Red(id) + ") error while sending authenticate message: " + colors.Red(err))
		}
		err = t.Clients[id].Connection.Close()
		if err != nil {
			logger.Error("Failed to close client (" + id + ") socket")
		}
		return
	} else {
		if t.Clients[id] == nil {
			return
		}

		logger.Good("User <" + colors.Blue(pk.Body.Info["User"].(string)) + "> " + colors.Green("Authenticated"))

		t.Clients[id].Authenticated = true
		t.Clients[id].ClientID = id

		err := t.SendEvent(id, events.Authenticated(true))
		if err != nil {
			logger.Error("client (" + colors.Red(id) + ") error while sending authenticate message:" + colors.Red(err))
		}
	}

	t.Clients[id].Username = pk.Body.Info["User"].(string)
	packageNewUser := events.ChatLog.NewUserConnected(t.Clients[id].Username)
	t.EventAppend(packageNewUser)
	t.EventBroadcast(id, packageNewUser)

	t.SendAllPackagesToNewClient(id)

	for {
		_, EventPackage, err := t.Clients[id].Connection.ReadMessage()

		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseAbnormalClosure) {
				logger.Warn("User <" + colors.Blue(t.Clients[id].Username) + "> " + colors.Red("Disconnected"))

				t.EventAppend(events.ChatLog.UserDisconnected(t.Clients[id].Username))
				t.RemoveClient(id)

				return
			} else {
				logger.Error("Error reading :", err.Error())
			}

			err := t.Clients[id].Connection.Close()
			if err != nil {
				logger.Error("Socket Error:", err.Error())
			}

			t.EventAppend(events.ChatLog.UserDisconnected(t.Clients[id].Username))
			t.RemoveClient(id)

			return
		}

		pk := t.Clients[id].Packager.CreatePackage(string(EventPackage))
		pk.Head.Time = time.Now().Format("02/01/2006 15:04:05")

		t.EventAppend(pk)
		t.DispatchEvent(pk)
	}
}

func (t *Teamserver) SetProfile(path string) {
	t.Profile = profile.NewProfile()
	err := t.Profile.SetProfile(path)
	if err != nil {
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
					)
					for _, User := range t.Profile.Config.Operators.Users {
						if User.Name == pk.Head.User {
							logger.Debug("Found User: " + User.Name)
							UserName = User.Name
							if User.Hashed {
								UserPassword = User.Password
								break
							} else {
								var hash = sha3.New256()
								hash.Write([]byte(User.Password))
								UserPassword = hex.EncodeToString(hash.Sum(nil))
								break
							}
						}
					}
					if pk.Body.Info["Password"].(string) == UserPassword {
						logger.Debug("User " + colors.Red(UserName) + " is authenticated")
						return true
					}
					logger.Debug("User is not authenticated...")
					return false
				} else {
					return false
				}
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
	for ClientID := range t.Clients {
		if ExceptClient != ClientID {
			err := t.SendEvent(ClientID, pk)
			if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
				logger.Error("SendEvent error: ", colors.Red(err))
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

	if t.Clients[id] != nil {

		if t.Clients[id] != nil {

			err = t.Clients[id].Connection.WriteMessage(websocket.BinaryMessage, buffer.Bytes())
			if err != nil {
				return err
			}

		} else {
			return fmt.Errorf("client (%v) doesn't exist anymore", colors.Red(id))
		}
	}

	return nil
}

func (t *Teamserver) RemoveClient(ClientID string) {
	if _, ok := t.Clients[ClientID]; ok {
		var (
			userDisconnected = t.Clients[ClientID].Username
			Authenticated    = t.Clients[ClientID].Authenticated
		)

		if Authenticated {
			t.EventBroadcast(ClientID, events.ChatLog.UserDisconnected(userDisconnected))
			for UserID := range t.Users {
				if userDisconnected == t.Users[UserID].Name {
					t.Users[UserID].Online = false
				}
			}
		}

		delete(t.Clients, ClientID)
	}
}

func (t *Teamserver) EventAppend(event packager.Package) []packager.Package {

	if event.Head.OneTime != "true" {
		t.EventsList = append(t.EventsList, event)
		return append(t.EventsList, event)
	} else {
		logger.Debug("Onetime package. not gonna save: ", event)
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
}

func (t *Teamserver) FindSystemPackages() bool {
	var err error

	if t.Profile.Config.Server.Build != nil {

		if len(t.Profile.Config.Server.Build.Compiler64) > 0 {
			t.Settings.Compiler64 = t.Profile.Config.Server.Build.Compiler64
		} else {
			t.Settings.Compiler64, err = exec.LookPath("x86_64-w64-mingw32-gcc")
			if err != nil {
				logger.Error("Couldn't find x64 mingw compiler: " + err.Error())
				return false
			}
		}

		if len(t.Profile.Config.Server.Build.Compiler86) > 0 {
			t.Settings.Compiler32 = t.Profile.Config.Server.Build.Compiler86
		} else {
			t.Settings.Compiler32, err = exec.LookPath("i686-w64-mingw32-gcc")
			if err != nil {
				logger.Error("Couldn't find x86 mingw compiler: " + err.Error())
				return false
			}
		}

		if len(t.Profile.Config.Server.Build.Nasm) > 0 {
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
			logger.Error("Couldn't find x64 mingw compiler: " + err.Error())
			return false
		}

		t.Settings.Compiler32, err = exec.LookPath("i686-w64-mingw32-gcc")
		if err != nil {
			logger.Error("Couldn't find x86 mingw compiler: " + err.Error())
			return false
		}

		t.Settings.Nasm, err = exec.LookPath("nasm")
		if err != nil {
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

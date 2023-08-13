package db

import (
	"errors"
	"fmt"
	"strconv"
	"encoding/base64"

	"Havoc/pkg/agent"
)

func (db *DB) AgentAdd(agent *agent.Agent) error {

	var err error
	var AgentID int64

	AgentID, err = strconv.ParseInt(agent.NameID, 16, 32)
	if err != nil {
		return err
	}

	/* check if it's a new db */
	if db.Existed() {

		/* check if agent already exists */
		if db.AgentExist(int(AgentID)) {
			return nil
		}

	} else {

		/* check if agent already exists */
		if db.AgentExist(int(AgentID)) {
			return errors.New(fmt.Sprintf("agent %x already exist in db", agent.NameID))
		}

	}

	/* prepare some arguments to execute for the sqlite db */
	stmt, err := db.db.Prepare("INSERT INTO TS_Agents ( AgentID, Active, Reason, AESKey, AESIv, Hostname, Username, DomainName, ExternalIP, InternalIP, ProcessName, BaseAddress, ProcessPID, ProcessTID, ProcessPPID, ProcessArch, Elevated, OSVersion, OSArch, SleepDelay, SleepJitter, KillDate, WorkingHours, FirstCallIn, LastCallIn) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
	if err != nil {
		return err
	}

	/* add the data to the agent table */
	_, err = stmt.Exec(
		int(AgentID),
		1,
		"",
		base64.StdEncoding.EncodeToString(agent.Encryption.AESKey),
		base64.StdEncoding.EncodeToString(agent.Encryption.AESIv),
		agent.Info.Hostname,
		agent.Info.Username,
		agent.Info.DomainName,
		agent.Info.ExternalIP,
		agent.Info.InternalIP,
		agent.Info.ProcessName,
		agent.Info.BaseAddress,
		agent.Info.ProcessPID,
		agent.Info.ProcessTID,
		agent.Info.ProcessPPID,
		agent.Info.ProcessArch,
		agent.Info.Elevated,
		agent.Info.OSVersion,
		agent.Info.OSArch,
		agent.Info.SleepDelay,
		agent.Info.SleepJitter,
		agent.Info.KillDate,
		agent.Info.WorkingHours,
		agent.Info.FirstCallIn,
		agent.Info.LastCallIn)
	if err != nil {
		return err
	}

	stmt.Close()

	return nil
}

func (db *DB) AgentUpdate(agent *agent.Agent) error {

	var err error
	var AgentID int64
	var active int

	AgentID, err = strconv.ParseInt(agent.NameID, 16, 32)
	if err != nil {
		return err
	}

	/* check if agent already exists */
	if db.AgentExist(int(AgentID)) == false {
		return errors.New("Agent does not exist")
	}

	/* prepare some arguments to execute for the sqlite db */
	stmt, err := db.db.Prepare("UPDATE TS_Agents SET Active = ?, Reason = ?, AESKey = ?, AESIv = ?, Hostname = ?, Username = ?, DomainName = ?, ExternalIP = ?, InternalIP = ?, ProcessName = ?, BaseAddress = ?, ProcessPID = ?, ProcessTID = ?, ProcessPPID = ?, ProcessArch = ?, Elevated = ?, OSVersion = ?, OSArch = ?, SleepDelay = ?, SleepJitter = ?, KillDate = ?, WorkingHours = ?, FirstCallIn = ?, LastCallIn = ? WHERE AgentID = ?")
	if err != nil {
		return err
	}

	if agent.Active {
		active = 1
	} else {
		active = 0
	}

	/* add the data to the agent table */
	_, err = stmt.Exec(
		active,
		agent.Reason,
		base64.StdEncoding.EncodeToString(agent.Encryption.AESKey),
		base64.StdEncoding.EncodeToString(agent.Encryption.AESIv),
		agent.Info.Hostname,
		agent.Info.Username,
		agent.Info.DomainName,
		agent.Info.ExternalIP,
		agent.Info.InternalIP,
		agent.Info.ProcessName,
		agent.Info.BaseAddress,
		agent.Info.ProcessPID,
		agent.Info.ProcessTID,
		agent.Info.ProcessPPID,
		agent.Info.ProcessArch,
		agent.Info.Elevated,
		agent.Info.OSVersion,
		agent.Info.OSArch,
		agent.Info.SleepDelay,
		agent.Info.SleepJitter,
		agent.Info.KillDate,
		agent.Info.WorkingHours,
		agent.Info.FirstCallIn,
		agent.Info.LastCallIn,
		int(AgentID))
	if err != nil {
		return err
	}

	stmt.Close()

	return nil
}

func (db *DB) AgentHasDied(AgentID int) bool {
	// prepare some arguments to execute for the sqlite db
	stmt, err := db.db.Prepare("UPDATE TS_Agents SET Active = 0 WHERE AgentID = ?")
	if err != nil {
		return false
	}

	// execute statment
	_, err = stmt.Exec(AgentID)
	stmt.Close()

	if err != nil {
		return false
	}

	return true
}

func (db *DB) AgentExist(AgentID int) bool {
	// prepare some arguments to execute for the sqlite db
	stmt, err := db.db.Prepare("SELECT COUNT(*) FROM TS_Agents WHERE AgentID = ?")
	if err != nil {
		return false
	}

	// execute statment
	query, err := stmt.Query(AgentID)
	defer query.Close()
	if err != nil {
		return false
	}

	for query.Next() {
		var NumRows int

		query.Scan(&NumRows)

		if NumRows == 1 {
			return true
		} else {
			return false
		}
	}

	return false
}

func (db *DB) AgentRemove(AgentID int) error {
	// prepare some arguments to execute for the sqlite db
	stmt, err := db.db.Prepare("DELETE FROM TS_Agents WHERE AgentID = ?")
	if err != nil {
		return err
	}

	// execute statment
	_, err = stmt.Exec(AgentID)
	stmt.Close()

	if err != nil {
		return err
	}

	return nil
}


func (db *DB) AgentAll() []*agent.Agent {

	var Agents []*agent.Agent

	query, err := db.db.Query("SELECT AgentID, Active, Reason, AESKey, AESIv, Hostname, Username, DomainName, ExternalIP, InternalIP, ProcessName, BaseAddress, ProcessPID, ProcessTID, ProcessPPID, ProcessArch, Elevated, OSVersion, OSArch, SleepDelay, SleepJitter, KillDate, WorkingHours, FirstCallIn, LastCallIn FROM TS_Agents WHERE Active = 1")
	if err != nil {
		return nil
	}
	defer query.Close()

	for query.Next() {

		var (
			AgentID int
			Active int
			Reason string
			AESKey string
			AESIv string
			Hostname string
			Username string
			DomainName string
			ExternalIP string
			InternalIP string
			ProcessName string
			BaseAddress int64
			ProcessPID int
			ProcessTID int
			ProcessPPID int
			ProcessArch string
			Elevated string
			OSVersion string
			OSArch string
			SleepDelay int
			SleepJitter int
			KillDate int64
			WorkingHours int32
			FirstCallIn string
			LastCallIn string
		)

		/* read the selected items */
		err = query.Scan(&AgentID, &Active, &Reason, &AESKey, &AESIv, &Hostname, &Username, &DomainName, &ExternalIP, &InternalIP, &ProcessName, &BaseAddress, &ProcessPID, &ProcessTID, &ProcessPPID, &ProcessArch, &Elevated, &OSVersion, &OSArch, &SleepDelay, &SleepJitter, &KillDate, &WorkingHours, &FirstCallIn, &LastCallIn)
		if err != nil {
			/* at this point we failed
			 * just return the collected agents */
			return Agents
		}

		BytesAESKey, _ := base64.StdEncoding.DecodeString(AESKey)
		BytesAESIv,  _ := base64.StdEncoding.DecodeString(AESIv)

		var Agent = &agent.Agent{
			Encryption: struct {
				AESKey []byte
				AESIv  []byte
			}{
				AESKey: BytesAESKey,
				AESIv:  BytesAESIv,
			},

			Active:     Active == 1,
			Reason:     Reason,
			SessionDir: "",

			Info: new(agent.AgentInfo),
		}

		Agent.NameID            = fmt.Sprintf("%08x", AgentID)
		Agent.SessionDir        = ""
		Agent.BackgroundCheck   = false
		Agent.TaskedOnce        = true
		Agent.Info.MagicValue   = agent.DEMON_MAGIC_VALUE
		Agent.Info.Listener     = nil
		Agent.Info.Hostname     = Hostname
		Agent.Info.Username     = Username
		Agent.Info.DomainName   = DomainName
		Agent.Info.ExternalIP   = ExternalIP
		Agent.Info.InternalIP   = InternalIP
		Agent.Info.ProcessName  = ProcessName
		Agent.Info.BaseAddress  = BaseAddress
		Agent.Info.ProcessPID   = ProcessPID
		Agent.Info.ProcessTID   = ProcessTID
		Agent.Info.ProcessPPID  = ProcessPPID
		Agent.Info.ProcessArch  = ProcessArch
		Agent.Info.Elevated     = Elevated
		Agent.Info.OSVersion    = OSVersion
		Agent.Info.OSArch       = OSArch
		Agent.Info.SleepDelay   = SleepDelay
		Agent.Info.SleepJitter  = SleepJitter
		Agent.Info.KillDate     = KillDate
		Agent.Info.WorkingHours = WorkingHours
		Agent.Info.FirstCallIn  = FirstCallIn
		Agent.Info.LastCallIn   = LastCallIn

		/* append collected agent to agent array */
		Agents = append(Agents, Agent)

	}

	return Agents
}

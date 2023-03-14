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
	stmt, err := db.db.Prepare("INSERT INTO TS_Agents (AgentID, AESKey, AESIv, Hostname, Username, DomainName, InternalIP, ProcessName, ProcessPID, ProcessPPID, ProcessArch, Elevated, OSVersion, OsArch, SleepDelay, SleepJitter) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
	if err != nil {
		return err
	}

	/* add the data to the agent table */
	_, err = stmt.Exec(
		int(AgentID),
		base64.StdEncoding.EncodeToString(agent.Encryption.AESKey),
		base64.StdEncoding.EncodeToString(agent.Encryption.AESIv),
		agent.Info.Hostname,
		agent.Info.Username,
		agent.Info.DomainName,
		agent.Info.InternalIP,
		agent.Info.ProcessName,
		agent.Info.ProcessPID,
		agent.Info.ProcessPPID,
		agent.Info.ProcessArch,
		agent.Info.Elevated,
		agent.Info.OSVersion,
		agent.Info.OSArch,
		agent.Info.SleepDelay,
		agent.Info.SleepJitter)
	if err != nil {
		return err
	}

	stmt.Close()

	return nil
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

package db

import (
	"errors"
	//"log"
)

func (db *DB) LinkAdd(ParentAgentID int, LinkAgentID int) error {

	var err error

	/* check if it's a new db */
	if db.Existed() {

		/* check if listener already exists */
		if db.LinkExist(ParentAgentID, LinkAgentID) {
			return nil
		}

	} else {

		/* check if listener already exists */
		if db.LinkExist(ParentAgentID, LinkAgentID) {
			return errors.New("Link already exist in db")
		}

	}

	/* prepare some arguments to execute for the sqlite db */
	stmt, err := db.db.Prepare("INSERT INTO TS_Links (ParentAgentID, LinkAgentID) values(?,?)")
	if err != nil {
		return err
	}

	/* add the data to the links table */
	_, err = stmt.Exec(ParentAgentID, LinkAgentID)
	if err != nil {
		return err
	}

	stmt.Close()

	return nil
}

func (db *DB) LinkExist(ParentAgentID int, LinkAgentID int) bool {
	// prepare some arguments to execute for the sqlite db
	stmt, err := db.db.Prepare("SELECT COUNT(*) FROM TS_Links WHERE ParentAgentID = ? AND LinkAgentID = ?")
	if err != nil {
		return false
	}

	// execute statment
	query, err := stmt.Query(ParentAgentID, LinkAgentID)
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

func (db *DB) ParentOf(AgentID int) (int, error) {
	var (
		ID  int
	)

	// prepare some arguments to execute for the sqlite db
	stmt, err := db.db.Prepare("SELECT ParentAgentID FROM TS_Links WHERE LinkAgentID = ?")
	if err != nil {
		return 0, err
	}

	// execute statment
	query, err := stmt.Query(AgentID)
	defer query.Close()
	if err != nil {
		return 0, err
	}

	for query.Next() {

		if err = query.Scan(&ID); err != nil {
			return 0, err
		}
		return ID, nil
	}

	return 0, errors.New("Parent not found")
}

func (db *DB) LinksOf(AgentID int) []int {
	var (
		ID  int
		IDs []int
	)

	// prepare some arguments to execute for the sqlite db
	stmt, err := db.db.Prepare("SELECT LinkAgentID FROM TS_Links WHERE ParentAgentID = ?")
	if err != nil {
		return IDs
	}

	// execute statment
	query, err := stmt.Query(AgentID)
	defer query.Close()
	if err != nil {
		return IDs
	}

	for query.Next() {

		if err = query.Scan(&ID); err != nil {
			return IDs
		}

		IDs = append(IDs, ID)

	}

	return IDs
}

func (db *DB) LinkRemove(ParentAgentID int, LinkAgentID int) error {
	// prepare some arguments to execute for the sqlite db
	stmt, err := db.db.Prepare("DELETE FROM TS_Links WHERE ParentAgentID = ? AND LinkAgentID = ?")
	if err != nil {
		return err
	}

	// execute statment
	_, err = stmt.Exec(ParentAgentID, LinkAgentID)
	stmt.Close()

	if err != nil {
		return err
	}

	return nil
}

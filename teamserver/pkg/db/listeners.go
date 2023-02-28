package db

import (
	"errors"
	"log"
)

func (db *DB) ListenerAdd(Name, Protocol, Config string) error {

	var err error

	/* check if it's a new db */
	if db.Existed() {

		/* check if listener already exists */
		if db.ListenerExist(Name) {
			return nil
		}

	} else {

		/* check if listener already exists */
		if db.ListenerExist(Name) {
			return errors.New("listener \"" + Name + "\"already exist in db")
		}

	}

	/* prepare some arguments to execute for the sqlite db */
	stmt, err := db.db.Prepare("INSERT INTO TS_Listeners (Name, Protocol, Config) values(?,?,?)")
	if err != nil {
		return err
	}

	/* add the data to the listener table */
	_, err = stmt.Exec(Name, Protocol, Config)
	if err != nil {
		return err
	}

	stmt.Close()

	return nil
}

func (db *DB) ListenerExist(Name string) bool {
	query, err := db.db.Query("SELECT Name FROM TS_Listeners")
	if err != nil {
		return false
	}
	defer query.Close()

	for query.Next() {
		var QueryName string

		query.Scan(&QueryName)

		if Name == QueryName {
			return true
		}
	}

	return false
}

func (db *DB) ListenerAll() []map[string]string {

	var Listeners []map[string]string

	query, err := db.db.Query("SELECT Name, Protocol, Config FROM TS_Listeners")
	if err != nil {
		return nil
	}
	defer query.Close()

	for query.Next() {

		var (
			Name string
			Prot string
			Conf string
			Data map[string]string
		)

		/* read the selected items */
		err = query.Scan(&Name, &Prot, &Conf)
		if err != nil {
			/* at this point we failed
			 * just return the collected listeners */
			return Listeners
		}

		Data = map[string]string{
			"Name":     Name,
			"Protocol": Prot,
			"Config":   Conf,
		}

		/* append collected listener to listener array */
		Listeners = append(Listeners, Data)

	}

	return Listeners
}

func (db *DB) ListenerCount() int {

	var Count int

	query, err := db.db.Query("SELECT COUNT(*) FROM TS_Listeners")
	if err != nil {
		return 0
	}
	defer query.Close()

	for query.Next() {
		if err = query.Scan(&Count); err != nil {
			log.Fatal(err)
		}
	}

	return Count
}

func (db *DB) ListenerNames() []string {
	var (
		Name  string
		Names []string
	)

	query, err := db.db.Query("SELECT Name FROM TS_Listeners")
	if err != nil {
		return nil
	}

	defer query.Close()

	for query.Next() {

		if err = query.Scan(&Name); err != nil {
			return Names
		}

		Names = append(Names, Name)

	}

	return Names
}

func (db *DB) ListenerRemove(Name string) error {
	// prepare some arguments to execute for the sqlite db
	stmt, err := db.db.Prepare("DELETE FROM TS_Listeners WHERE Name = ?")
	if err != nil {
		return err
	}

	// execute statment
	_, err = stmt.Exec(Name)
	stmt.Close()

	if err != nil {
		return err
	}

	return nil
}

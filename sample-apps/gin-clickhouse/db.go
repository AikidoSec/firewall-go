package main

import (
	"database/sql"
	_ "github.com/ClickHouse/clickhouse-go"
	"log"
)

// Pet represents a pet entity
type Pet struct {
	ID    int
	Name  string
	Owner string
}

// DatabaseHelper provides methods to interact with the database
type DatabaseHelper struct {
	db *sql.DB
}

// NewDatabaseHelper creates a new DatabaseHelper
func NewDatabaseHelper() *DatabaseHelper {
	db := connectToDb()
	return &DatabaseHelper{db: db}
}

// GetAllPets retrieves all pets from the database
func (dh *DatabaseHelper) GetAllPets() ([]Pet, error) {
	var pets []Pet
	rows, err := dh.db.Query("SELECT pet_id, pet_name, owner FROM pets")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var pet Pet
		if err := rows.Scan(&pet.ID, &pet.Name, &pet.Owner); err != nil {
			return nil, err
		}
		pets = append(pets, pet)
	}
	return pets, nil
}

// CreatePetByName inserts a new pet into the database
func (dh *DatabaseHelper) CreatePetByName(petName string) (int64, error) {
	// Prepare the insert statement with placeholders
	statement, err := dh.db.Prepare("INSERT INTO pets (pet_name, owner) VALUES (?, 'Aikido Security')")
	if err != nil {
		return 0, err
	}
	defer statement.Close()

	// Start the transaction
	tx, err := dh.db.Begin()
	if err != nil {
		log.Fatal(err)
		return 0, err
	}

	// Execute the statement with the petName parameter
	_, err = tx.Stmt(statement).Exec(petName)
	if err != nil {
		// Rollback the transaction in case of an error
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			log.Fatal(rollbackErr)
		}
		return 0, err
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		log.Fatal(err)
		return 0, err
	}
	return 1, nil // ClickHouse does not return the ID of the inserted row
}

// Close closes the database connection
func (dh *DatabaseHelper) Close() error {
	return dh.db.Close()
}

func connectToDb() *sql.DB {
	var err error
	var db *sql.DB
	// Connect to ClickHouse
	connStr := "tcp://localhost:9000?username=user&password=password&database=db"
	db, err = sql.Open("clickhouse", connStr)
	if err != nil {
		log.Fatal(err)
	}

	// Ping the database to check if the connection is establishedpetName
	if err := db.Ping(); err != nil {
		log.Fatal(err)
	}

	return db
}

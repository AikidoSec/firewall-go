package main

import (
	"context"
	"database/sql"
	"errors"
	"log"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

// Pet represents a pet entity
type Pet struct {
	ID    int    `db:"pet_id"`
	Name  string `db:"pet_name"`
	Owner string `db:"owner"`
}

// DatabaseHelper provides methods to interact with the database
type DatabaseHelper struct {
	db *sqlx.DB
}

// NewDatabaseHelper creates a new DatabaseHelper
func NewDatabaseHelper() *DatabaseHelper {
	db := connectToDb()
	return &DatabaseHelper{db: db}
}

// GetAllPets retrieves all pets from the database
func (dh *DatabaseHelper) GetAllPets(ctx context.Context) ([]Pet, error) {
	var pets []Pet
	err := dh.db.SelectContext(ctx, &pets, "SELECT pet_id, pet_name, owner FROM pets")
	if err != nil {
		return nil, err
	}
	return pets, nil
}

// GetPetByID retrieves a pet by its ID
func (dh *DatabaseHelper) GetPetByID(ctx context.Context, id int) (Pet, error) {
	var pet Pet
	err := dh.db.GetContext(ctx, &pet, "SELECT pet_id, pet_name, owner FROM pets WHERE pet_id = $1", id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Pet{ID: 0, Name: "Unknown", Owner: "Unknown"}, nil
		}
		return Pet{}, err
	}
	return pet, nil
}

// CreatePetByName inserts a new pet into the database
func (dh *DatabaseHelper) CreatePetByName(ctx context.Context, petName string) (int64, error) {
	// Intentionally vulnerable to SQL injection
	sqlStatement := "INSERT INTO pets (pet_name, owner) VALUES ('" + petName + "', 'Aikido Security') RETURNING pet_id"
	var petID int64
	err := dh.db.QueryRowxContext(ctx, sqlStatement).Scan(&petID)
	if err != nil {
		return 0, err // Return 0 and the error if something goes wrong
	}
	return petID, nil // Return the petID and nil error if successful
}

// Close closes the database connection
func (dh *DatabaseHelper) Close() error {
	return dh.db.Close()
}

func connectToDb() *sqlx.DB {
	var err error
	var db *sqlx.DB
	// Connect to PostgreSQL
	connStr := "postgresql://localhost:5432/db?user=user&password=password&sslmode=disable"
	db, err = sqlx.Connect("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	// Ping the database to check if the connection is established
	if err := db.Ping(); err != nil {
		log.Fatal(err)
	}

	return db
}

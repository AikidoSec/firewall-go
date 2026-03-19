package main

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
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
	err := dh.db.GetContext(ctx, &pet, "SELECT pet_id, pet_name, owner FROM pets WHERE pet_id = ?", id)
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
	sqlStatement := "INSERT INTO pets (pet_name, owner) VALUES ('" + petName + "', 'Aikido Security')"
	result, err := dh.db.ExecContext(ctx, sqlStatement)
	if err != nil {
		return 0, err // Return 0 and the error if something goes wrong
	}
	return result.LastInsertId() // Return the petID and nil error if successful
}

// Close closes the database connection
func (dh *DatabaseHelper) Close() error {
	return dh.db.Close()
}

func connectToDb() *sqlx.DB {
	// Connect to MySQL
	connStr := "user:password@tcp(localhost:3306)/db"
	for range 30 {
		db, err := sqlx.Connect("mysql", connStr)
		if err == nil {
			return db
		}
		log.Println("Waiting for database...", err)
		time.Sleep(2 * time.Second)
	}
	log.Fatal("Could not connect to database after 30 attempts")
	return nil
}

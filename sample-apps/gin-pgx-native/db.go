package main

import (
	"context"
	"errors"
	"log"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Pet represents a pet entity
type Pet struct {
	ID    int
	Name  string
	Owner string
}

// DatabaseHelper provides methods to interact with the database
type DatabaseHelper struct {
	pool *pgxpool.Pool
}

// NewDatabaseHelper creates a new DatabaseHelper
func NewDatabaseHelper() *DatabaseHelper {
	pool := connectToDb()
	return &DatabaseHelper{pool: pool}
}

// GetAllPets retrieves all pets from the database
func (dh *DatabaseHelper) GetAllPets(ctx context.Context) ([]Pet, error) {
	var pets []Pet
	rows, err := dh.pool.Query(ctx, "SELECT pet_id, pet_name, owner FROM pets")
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

// GetPetByID retrieves a pet by its ID
func (dh *DatabaseHelper) GetPetByID(ctx context.Context, id int) (Pet, error) {
	var pet Pet
	err := dh.pool.QueryRow(ctx, "SELECT pet_id, pet_name, owner FROM pets WHERE pet_id = $1", id).Scan(&pet.ID, &pet.Name, &pet.Owner)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
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
	err := dh.pool.QueryRow(ctx, sqlStatement).Scan(&petID)
	if err != nil {
		return 0, err // Return 0 and the error if something goes wrong
	}
	return petID, nil // Return the petID and nil error if successful
}

// Close closes the database connection
func (dh *DatabaseHelper) Close() error {
	dh.pool.Close()
	return nil
}

func connectToDb() *pgxpool.Pool {
	var err error
	var pool *pgxpool.Pool
	// Connect to PostgreSQL
	connStr := "postgresql://localhost:5432/db?user=user&password=password"
	pool, err = pgxpool.New(context.Background(), connStr)
	if err != nil {
		log.Fatal(err)
	}

	// Ping the database to check if the connection is established
	if err := pool.Ping(context.Background()); err != nil {
		log.Fatal(err)
	}

	return pool
}

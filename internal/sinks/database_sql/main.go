package database_sql

import "fmt"

func Examine(query string) error {
	fmt.Println("Examining query:", query)
	return nil
}

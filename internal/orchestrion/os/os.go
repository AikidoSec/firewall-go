package os

import (
	"errors"
	"strings"
)

func Examine(path string) error {
	if strings.Contains(path, "blogs") {
		return errors.New("Attack detected")
	}
	return nil
}

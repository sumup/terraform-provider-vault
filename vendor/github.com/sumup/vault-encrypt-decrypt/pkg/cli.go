package pkg

import (
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"syscall"
)

func ReadFromStdin(promptMessage string) ([]byte, error) {
	fmt.Print(promptMessage)
	value, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return nil, fmt.Errorf("Error while reading input value from stdin. Err :%s\n", err)
	}

	if value == nil {
		return nil, errors.New("Empty value")
	}

	return value, nil
}

package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
)

func executeShellCommand(command string) (string, error) {
	var output bytes.Buffer
	// #nosec G204 G702 - intentional command injection vulnerability
	cmd := exec.Command("sh", "-c", command)
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	if err != nil {
		return "", err
	}
	return output.String(), nil
}

func makeHTTPRequest(url string) string {
	// #nosec - this is an intentional vulnerability
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Sprintf("Error: %s", err.Error())
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Sprintf("Error: %s", err.Error())
	}
	return string(body)
}

func readFile(filePath string) (string, error) {
	// #nosec G304 G703 - intentional path traversal vulnerability
	content, err := os.ReadFile("content/blogs/" + filePath)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
)

// executeShellCommand executes a shell command and returns the output.
func executeShellCommand(command string) string {
	var output bytes.Buffer
	cmd := exec.Command("sh", "-c", command)
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	if err != nil {
		return fmt.Sprintf("Error: %s", err.Error())
	}
	return output.String()
}

// makeHTTPRequest makes a simple HTTP GET request and returns the response.
func makeHTTPRequest(url string) string {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Sprintf("Error: %s", err.Error())
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Sprintf("Error: %s", err.Error())
	}
	return string(body)
}

// readFile reads the content of a file and returns it as a string.
func readFile(filePath string) string {
	content, err := os.ReadFile("content/blogs/" + filePath)
	if err != nil {
		return fmt.Sprintf("Error: %s", err.Error())
	}
	return string(content)
}

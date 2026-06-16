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

// makeHTTPRequest makes a simple HTTP GET request and returns the response.
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

// readFile reads the content of a file and returns it as a string. The read
// runs in a child goroutine to exercise automatic request-context propagation:
// the path traversal must still be detected on the spawned goroutine.
func readFile(filePath string) (string, error) {
	type result struct {
		content []byte
		err     error
	}
	ch := make(chan result, 1)
	go func() {
		// #nosec G304 G703 - intentional path traversal vulnerability
		content, err := os.ReadFile("content/blogs/" + filePath)
		ch <- result{content: content, err: err}
	}()
	r := <-ch
	if r.err != nil {
		return "", r.err
	}
	return string(r.content), nil
}

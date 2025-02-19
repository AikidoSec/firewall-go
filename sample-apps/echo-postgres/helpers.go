package main

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"os/exec"
)

// executeShellCommand executes a shell command and returns the output.
func executeShellCommand(command string) (string, error) {
	var output bytes.Buffer
	cmd := exec.Command("sh", "-c", command)
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	if err != nil {
		return "", err
	}
	return output.String(), nil
}

// makeHttpRequest makes a simple HTTP GET request and returns the response.
func makeHttpRequest(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// readFile reads the content of a file and returns it as a string.
func readFile(filePath string) (string, error) {
	content, err := ioutil.ReadFile("content/blogs/" + filePath)
	if err != nil {

		return "", err
	}
	return string(content), nil
}

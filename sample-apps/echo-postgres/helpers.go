package main

import (
	"bytes"
	"io/ioutil"
	"net/http"
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
		panic(err)
	}
	return output.String()
}

// makeHttpRequest makes a simple HTTP GET request and returns the response.
func makeHttpRequest(url string) string {
	resp, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	return string(body)
}

// readFile reads the content of a file and returns it as a string.
func readFile(filePath string) string {
	content, err := ioutil.ReadFile("content/blogs/" + filePath)
	if err != nil {

		panic(err)
	}
	return string(content)
}

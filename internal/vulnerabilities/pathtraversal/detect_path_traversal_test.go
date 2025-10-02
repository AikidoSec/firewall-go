package pathtraversal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetectPathTraversal(t *testing.T) {
	t.Run("empty user input", func(t *testing.T) {
		assert.False(t, detectPathTraversal("test.txt", "", true))
	})

	t.Run("empty file input", func(t *testing.T) {
		assert.False(t, detectPathTraversal("", "test", true))
	})

	t.Run("empty user input and file input", func(t *testing.T) {
		assert.False(t, detectPathTraversal("", "", true))
	})

	t.Run("user input is a single character", func(t *testing.T) {
		assert.False(t, detectPathTraversal("test.txt", "t", true))
	})

	t.Run("file input is a single character", func(t *testing.T) {
		assert.False(t, detectPathTraversal("t", "test", true))
	})

	t.Run("same as user input", func(t *testing.T) {
		assert.False(t, detectPathTraversal("text.txt", "text.txt", true))
	})

	t.Run("with directory before", func(t *testing.T) {
		assert.False(t, detectPathTraversal("directory/text.txt", "text.txt", true))
	})

	t.Run("with both directory before", func(t *testing.T) {
		assert.False(t, detectPathTraversal("directory/text.txt", "directory/text.txt", true))
	})

	t.Run("user input and file input are single characters", func(t *testing.T) {
		assert.False(t, detectPathTraversal("t", "t", true))
	})

	t.Run("it flags ../", func(t *testing.T) {
		assert.True(t, detectPathTraversal("../test.txt", "../", true))
	})

	t.Run("it flags ..\\", func(t *testing.T) {
		assert.True(t, detectPathTraversal("..\\test.txt", "..\\", true))
	})

	t.Run("it flags ../../", func(t *testing.T) {
		assert.True(t, detectPathTraversal("../../test.txt", "../../", true))
	})

	t.Run("it flags ..\\..\\", func(t *testing.T) {
		assert.True(t, detectPathTraversal("..\\..\\test.txt", "..\\..\\", true))
	})

	t.Run("it flags ../../../../", func(t *testing.T) {
		assert.True(t, detectPathTraversal("../../../../test.txt", "../../../../", true))
	})

	t.Run("it flags ..\\..\\..\\", func(t *testing.T) {
		assert.True(t, detectPathTraversal("..\\..\\..\\test.txt", "..\\..\\..\\", true))
	})

	t.Run("it flags ./../", func(t *testing.T) {
		assert.True(t, detectPathTraversal("./../test.txt", "./../", true))
	})

	t.Run("user input is longer than file path", func(t *testing.T) {
		assert.False(t, detectPathTraversal("../file.txt", "../../file.txt", true))
	})

	t.Run("absolute linux path", func(t *testing.T) {
		assert.True(t, detectPathTraversal("/etc/passwd", "/etc/passwd", true))
	})

	t.Run("linux user directory", func(t *testing.T) {
		assert.True(t, detectPathTraversal("/home/user/file.txt", "/home/user/", true))
	})

	t.Run("possible bypass", func(t *testing.T) {
		assert.True(t, detectPathTraversal("/./etc/passwd", "/./etc/passwd", true))
	})
	t.Run("another bypass", func(t *testing.T) {
		assert.True(t, detectPathTraversal("/./././root/test.txt", "/./././root/test.txt", true))
		assert.True(t, detectPathTraversal("/./././root/test.txt", "/./././root", true))
	})

	t.Run("no path traversal", func(t *testing.T) {
		assert.False(t, detectPathTraversal("/appdata/storage/file.txt", "/storage/file.txt", true))
	})

	t.Run("does not flag test", func(t *testing.T) {
		assert.False(t, detectPathTraversal("/app/test.txt", "test", true))
	})

	t.Run("does not flag example/test.txt", func(t *testing.T) {
		assert.False(t, detectPathTraversal("/app/data/example/test.txt", "example/test.txt", true))
	})

	t.Run("does not absolute path with different folder", func(t *testing.T) {
		assert.False(t, detectPathTraversal("/etc/app/config", "/etc/hack/config", true))
	})

	t.Run("does not absolute path inside another folder", func(t *testing.T) {
		assert.False(t, detectPathTraversal("/etc/app/data/etc/config", "/etc/config", true))
	})

	t.Run("disable checkPathStart", func(t *testing.T) {
		assert.False(t, detectPathTraversal("/etc/passwd", "/etc/passwd", false))
	})

	t.Run("does not detect if user input path contains no filename or subfolder", func(t *testing.T) {
		assert.False(t, detectPathTraversal("/etc/app/test.txt", "/etc/", true))
		assert.False(t, detectPathTraversal("/etc/app/", "/etc/", true))
		assert.False(t, detectPathTraversal("/etc/app/", "/etc", true))
		assert.False(t, detectPathTraversal("/etc/", "/etc/", true))
		assert.False(t, detectPathTraversal("/etc", "/etc", true))
		assert.False(t, detectPathTraversal("/var/a", "/var/", true))
		assert.False(t, detectPathTraversal("/var/a", "/var/b", true))
		assert.False(t, detectPathTraversal("/var/a", "/var/b/test.txt", true))
	})

	t.Run("it does detect if user input path contains a filename or subfolder", func(t *testing.T) {
		assert.True(t, detectPathTraversal("/etc/app/file.txt", "/etc/app", true))
		assert.True(t, detectPathTraversal("/etc/app/file.txt", "/etc/app/file.txt", true))
		assert.True(t, detectPathTraversal("/var/backups/file.txt", "/var/backups", true))
		assert.True(t, detectPathTraversal("/var/backups/file.txt", "/var/backups/file.txt", true))
		assert.True(t, detectPathTraversal("/var/a", "/var/a", true))
		assert.True(t, detectPathTraversal("/var/a/b", "/var/a", true))
		assert.True(t, detectPathTraversal("/var/a/b/test.txt", "/var/a", true))
	})
}

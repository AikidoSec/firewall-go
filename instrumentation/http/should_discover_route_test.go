package http

import (
	"testing"
)

func TestShouldDiscoverRoute(t *testing.T) {
	t.Run("it does not discover route if not found or method not allowed", func(t *testing.T) {
		if shouldDiscoverRoute(404, "/", "GET") != false {
			t.Errorf("Expected false, got true")
		}
		if shouldDiscoverRoute(405, "/", "GET") != false {
			t.Errorf("Expected false, got true")
		}
	})

	t.Run("it discovers route for all non error status codes", func(t *testing.T) {
		if shouldDiscoverRoute(200, "/", "GET") != true {
			t.Errorf("Expected true, got false")
		}
		if shouldDiscoverRoute(500, "/", "GET") != false {
			t.Errorf("Expected false, got true")
		}
		if shouldDiscoverRoute(400, "/", "GET") != false {
			t.Errorf("Expected false, got true")
		}
		if shouldDiscoverRoute(300, "/", "GET") != true {
			t.Errorf("Expected true, got false")
		}
		if shouldDiscoverRoute(201, "/", "GET") != true {
			t.Errorf("Expected true, got false")
		}
	})

	t.Run("it does not discover route for OPTIONS or HEAD methods", func(t *testing.T) {
		if shouldDiscoverRoute(200, "/", "OPTIONS") != false {
			t.Errorf("Expected false, got true")
		}
		if shouldDiscoverRoute(200, "/", "HEAD") != false {
			t.Errorf("Expected false, got true")
		}
	})

	t.Run("it does not discover route for OPTIONS or HEAD methods even with other status codes", func(t *testing.T) {
		if shouldDiscoverRoute(404, "/", "OPTIONS") != false {
			t.Errorf("Expected false, got true")
		}
		if shouldDiscoverRoute(405, "/", "HEAD") != false {
			t.Errorf("Expected false, got true")
		}
	})

	t.Run("it does not discover static files", func(t *testing.T) {
		if shouldDiscoverRoute(200, "/service-worker.js", "GET") != false {
			t.Errorf("Expected false, got true")
		}
		if shouldDiscoverRoute(200, "/precache-manifest.10faec0bee24db502c8498078126dd53.js", "POST") != false {
			t.Errorf("Expected false, got true")
		}
		if shouldDiscoverRoute(200, "/img/icons/favicon-16x16.png", "GET") != false {
			t.Errorf("Expected false, got true")
		}
		if shouldDiscoverRoute(200, "/fonts/icomoon.ttf", "GET") != false {
			t.Errorf("Expected false, got true")
		}
	})

	t.Run("it allows html and php files", func(t *testing.T) {
		if shouldDiscoverRoute(200, "/index.html", "GET") != true {
			t.Errorf("Expected true, got false")
		}
		if shouldDiscoverRoute(200, "/contact.html", "GET") != true {
			t.Errorf("Expected true, got false")
		}
		if shouldDiscoverRoute(200, "/index.php", "GET") != true {
			t.Errorf("Expected true, got false")
		}
		if shouldDiscoverRoute(200, "/contact.php", "GET") != true {
			t.Errorf("Expected true, got false")
		}
	})

	t.Run("it allows files with extension of one character", func(t *testing.T) {
		if shouldDiscoverRoute(200, "/a.a", "GET") != true {
			t.Errorf("Expected true, got false")
		}
	})

	t.Run("it allows files with extension of 6 or more characters", func(t *testing.T) {
		if shouldDiscoverRoute(200, "/a.aaaaaa", "GET") != true {
			t.Errorf("Expected true, got false")
		}
		if shouldDiscoverRoute(200, "/a.aaaaaaa", "GET") != true {
			t.Errorf("Expected true, got false")
		}
	})

	t.Run("it ignores files that end with .properties", func(t *testing.T) {
		if shouldDiscoverRoute(200, "/file.properties", "GET") != false {
			t.Errorf("Expected false, got true")
		}
		if shouldDiscoverRoute(200, "/directory/file.properties", "GET") != false {
			t.Errorf("Expected false, got true")
		}
	})

	t.Run("it ignores files or directories that start with dot", func(t *testing.T) {
		if shouldDiscoverRoute(200, "/.env", "GET") != false {
			t.Errorf("Expected false, got true")
		}
		if shouldDiscoverRoute(200, "/.aws/credentials", "GET") != false {
			t.Errorf("Expected false, got true")
		}
		if shouldDiscoverRoute(200, "/directory/.gitconfig", "GET") != false {
			t.Errorf("Expected false, got true")
		}
		if shouldDiscoverRoute(200, "/hello/.gitignore/file", "GET") != false {
			t.Errorf("Expected false, got true")
		}
	})

	// t.Run("it ignores files that end with php (used as directory)", func(t *testing.T) {
	// 	if ShouldDiscoverRoute(200, "/file.php", "GET") != false {
	// 		t.Errorf("Expected false, got true")
	// 	}
	// 	if ShouldDiscoverRoute(200, "/app_dev.php/_profiler/phpinfo", "GET") != false {
	// 		t.Errorf("Expected false, got true")
	// 	}
	// })

	t.Run("it allows .well-known directory", func(t *testing.T) {
		if shouldDiscoverRoute(200, "/.well-known", "GET") != true {
			t.Errorf("Expected true, got false")
		}
		if shouldDiscoverRoute(200, "/.well-known/change-password", "GET") != true {
			t.Errorf("Expected true, got false")
		}
		if shouldDiscoverRoute(200, "/.well-known/security.txt", "GET") != false {
			t.Errorf("Expected false, got true")
		}
	})

	t.Run("it ignores certain strings", func(t *testing.T) {
		if shouldDiscoverRoute(200, "/cgi-bin/luci/;stok=/locale", "GET") != false {
			t.Errorf("Expected false, got true")
		}
		if shouldDiscoverRoute(200, "/whatever/cgi-bin", "GET") != false {
			t.Errorf("Expected false, got true")
		}
	})

	t.Run("it should ignore fonts", func(t *testing.T) {
		if shouldDiscoverRoute(200, "/fonts/icomoon.ttf", "GET") != false {
			t.Errorf("Expected false, got true")
		}
		if shouldDiscoverRoute(200, "/fonts/icomoon.woff", "GET") != false {
			t.Errorf("Expected false, got true")
		}
		if shouldDiscoverRoute(200, "/fonts/icomoon.woff2", "GET") != false {
			t.Errorf("Expected false, got true")
		}
	})

	t.Run("it ignores files that end with .config", func(t *testing.T) {
		if shouldDiscoverRoute(200, "/blog/App_Config/ConnectionStrings.config", "GET") != false {
			t.Errorf("Expected false, got true")
		}
	})

}

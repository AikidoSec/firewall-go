package attackwave

import "strings"

// suspiciousDirectories contains directory names commonly targeted by web scanners
var suspiciousDirectories map[string]bool

func init() {
	dirs := []string{
		".",
		"..",
		".anydesk",
		".aptitude",
		".aws",
		".azure",
		".cache",
		".circleci",
		".config",
		".dbus",
		".docker",
		".drush",
		".gem",
		".git",
		".github",
		".gnupg",
		".gsutil",
		".hg",
		".idea",
		".java",
		".kube",
		".lftp",
		".minikube",
		".npm",
		".nvm",
		".pki",
		".snap",
		".ssh",
		".subversion",
		".svn",
		".tconn",
		".thunderbird",
		".tor",
		".vagrant.d",
		".vidalia",
		".vim",
		".vmware",
		".vscode",
		"%systemroot%",
		"apache",
		"apache2",
		"cgi-bin",
		"grub",
		"System32",
		"tmp",
		"xampp",
	}

	suspiciousDirectories = make(map[string]bool, len(dirs))
	for _, dir := range dirs {
		suspiciousDirectories[strings.ToLower(dir)] = true
	}
}

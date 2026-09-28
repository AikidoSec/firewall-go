# Track custom events

Use `zen.Track()` to report events that only your application knows about, such as failed logins. [Playbooks](https://help.aikido.dev/zen-firewall/zen-features/playbooks) can act when an event occurs repeatedly, for example by blocking an IP after three failed logins in five minutes.

Call `zen.Track()` from an HTTP handler with the current request context:

```go
http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
	user, err := authenticate(r)
	if err != nil {
		zen.Track(r.Context(), "user.login_failed")
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	zen.SetUser(r.Context(), user.ID, user.Name)
	zen.Track(r.Context(), "user.login_succeeded")
	w.WriteHeader(http.StatusNoContent)
})
```

After adding `zen.Track()`, trigger the event at least once. It will then appear on the Playbooks page in the Aikido dashboard. From there, you can create a playbook and choose what should happen when the event occurs. Calling `zen.Track()` by itself does not create a playbook or block anything.

Call `zen.Track()` while handling an HTTP request. Zen associates the event with the request's IP address. Playbook counts are per IP, not across your whole app. If you call `zen.SetUser()` before `zen.Track()`, Zen also includes the current user. `zen.SetUser()` is optional.

Event names can use any format, but must not be empty. We recommend lowercase, dot-separated names such as `user.login_failed`.

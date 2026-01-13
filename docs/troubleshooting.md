# Troubleshooting

## Review installation steps

Double-check your setup against the [installation guide](../README.md#installation).

Make sure:

- Your runtime and framework are supported (see [Supported libraries and frameworks](../README.md#supported-libraries-and-frameworks)).
- The package installed successfully.
- Your framework-specific integration matches the example in the docs (for Gin, see the example in [docs/gin.md](../docs/gin.md)).

## Check connection to Aikido

The firewall must be able to reach Aikido’s API endpoints.

Test from the same environment where your app runs and follow the instructions on this page: https://help.aikido.dev/zen-firewall/miscellaneous/outbound-network-connections-for-zen

## Check logs for errors

Common places:

- Docker: `docker logs <your-app-container>`
- systemd: `journalctl -u <your-app-service> --since "1 hour ago"`
- Local dev: your terminal or IDE run console

Tip: search for lines that contain `Aikido` or `Zen` to spot initialization and request logs.

## Enable debug logging

Set the environment variable `AIKIDO_DEBUG` to `true` and check the log output of your application.

## Contact support

If you still can’t resolve the issue:

- Use the [in-app chat](https://app.aikido.dev/) to reach our support team directly.
- Or create an issue on [GitHub](https://github.com/AikidoSec/firewall-go/issues) with details about your setup, framework, and logs.

Include as much context as possible (framework, logs, and how Aikido was added) so we can help you quickly.

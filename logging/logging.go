package logging

import (
	"os"

	logging "github.com/op/go-logging"
)

// Log global logger
var Log = logging.MustGetLogger("ec2.cli")
var logFormat = logging.MustStringFormatter(
	`%{color}%{time:15:04:05.000} %{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}`,
)
var backend = logging.NewLogBackend(os.Stderr, "", 0)
var formatter = logging.NewBackendFormatter(backend, logFormat)

func init() {
	logging.SetBackend(formatter)
}

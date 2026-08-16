package scanguard

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Traefik's logging story for plugins is poor: fmt.Println from interpreted
// plugin code is emitted at DEBUG level (invisible at Traefik's default log
// level) and the standard log package is emitted at ERROR. Neither gives a
// security tool a usable, machine-readable audit trail.
//
// So scanguard writes its own JSON lines directly to stdout. They interleave
// cleanly with Traefik's own JSON logs, survive at any Traefik log level, and can
// be scraped by Loki/Promtail or acted on by an external fail2ban.

var logMu sync.Mutex

type logLine struct {
	Time     string      `json:"time"`
	Level    string      `json:"level"`
	Logger   string      `json:"logger"`
	Instance string      `json:"instance,omitempty"`
	Msg      string      `json:"msg"`
	Fields   interface{} `json:"fields,omitempty"`
}

func emit(level, instance, msg string, fields interface{}) {
	line := logLine{
		Time:     time.Now().UTC().Format(time.RFC3339Nano),
		Level:    level,
		Logger:   "scanguard",
		Instance: instance,
		Msg:      msg,
		Fields:   fields,
	}
	buf, err := json.Marshal(line)
	if err != nil {
		return
	}
	buf = append(buf, '\n')

	logMu.Lock()
	_, _ = os.Stdout.Write(buf)
	logMu.Unlock()
}

func logInfo(instance, msg string, fields interface{})  { emit("info", instance, msg, fields) }
func logWarn(instance, msg string, fields interface{})  { emit("warn", instance, msg, fields) }
func logError(instance, msg string, fields interface{}) { emit("error", instance, msg, fields) }

// warnedOnce keys warnings that describe a persistent misconfiguration. Emitting
// those per request would be its own denial of service against the log pipeline.
var (
	warnedMu sync.Mutex
	warned   = map[string]struct{}{}
)

func warnOnce(instance, key, msg string, fields interface{}) {
	warnedMu.Lock()
	if _, seen := warned[instance+"\x00"+key]; seen {
		warnedMu.Unlock()
		return
	}
	warned[instance+"\x00"+key] = struct{}{}
	warnedMu.Unlock()

	logWarn(instance, msg, fields)
}

// recoverPanic must be deferred at the top of every goroutine this plugin
// spawns. Traefik's recovery middleware only wraps the request path — a panic in
// a plugin-spawned goroutine takes down the entire Traefik process, and with it
// every site behind it.
func recoverPanic(instance, where string) {
	if r := recover(); r != nil {
		logError(instance, "recovered from panic in background goroutine", map[string]interface{}{
			"where": where,
			"panic": jsonSafe(r),
		})
	}
}

// jsonSafe renders an arbitrary recovered value as something json.Marshal accepts.
func jsonSafe(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return "<nil>"
	case string:
		return t
	case error:
		return t.Error()
	default:
		buf, err := json.Marshal(t)
		if err != nil {
			return "unprintable panic value"
		}
		return string(buf)
	}
}

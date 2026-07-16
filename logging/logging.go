package logging

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

type Level int

const (
	DEBUG Level = iota
	INFO
	WARN
	ERROR
	FATAL
)

func (l Level) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	case FATAL:
		return "FATAL"
	}
	return "UNKNOWN"
}

type Logger struct {
	name   string
	level  Level
	output *log.Logger
	mu     sync.Mutex
}

var (
	rootLogger = log.New(os.Stdout, "", 0)
	globalMu   sync.Mutex
	loggers    = make(map[string]*Logger)
)

func Get(name string) *Logger {
	globalMu.Lock()
	defer globalMu.Unlock()

	if l, ok := loggers[name]; ok {
		return l
	}

	l := &Logger{
		name:   name,
		level:  INFO,
		output: rootLogger,
	}
	loggers[name] = l
	return l
}

func SetLevel(name string, level Level) {
	globalMu.Lock()
	defer globalMu.Unlock()

	if l, ok := loggers[name]; ok {
		l.mu.Lock()
		l.level = level
		l.mu.Unlock()
	}
}

func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

func (l *Logger) log(level Level, format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if level < l.level {
		return
	}

	msg := fmt.Sprintf(format, args...)
	ts := time.Now().Format("15:04:05.000")
	l.output.Printf("[%s] %-5s [%s] %s", ts, level, l.name, msg)
}

func (l *Logger) Infof(format string, args ...interface{}) {
	l.log(INFO, format, args...)
}

func (l *Logger) Warnf(format string, args ...interface{}) {
	l.log(WARN, format, args...)
}

func (l *Logger) Errorf(format string, args ...interface{}) {
	l.log(ERROR, format, args...)
}

func (l *Logger) Debugf(format string, args ...interface{}) {
	l.log(DEBUG, format, args...)
}

func (l *Logger) Fatalf(format string, args ...interface{}) {
	l.log(FATAL, format, args...)
	os.Exit(1)
}

// LevelFromString parses a level string ("debug", "info", "warn", "error", "fatal")
func LevelFromString(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return DEBUG
	case "info":
		return INFO
	case "warn", "warning":
		return WARN
	case "error":
		return ERROR
	case "fatal":
		return FATAL
	default:
		return INFO
	}
}

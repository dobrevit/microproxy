package microproxy

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
)

// Logger is where the proxy reports what it is doing and what went wrong. It is
// the shape goproxy expects, so a *log.Logger satisfies it as is.
type Logger interface {
	Printf(format string, v ...interface{})
}

// LoggerFunc adapts a function to Logger.
type LoggerFunc func(format string, v ...interface{})

// Printf implements Logger.
func (f LoggerFunc) Printf(format string, v ...interface{}) { f(format, v...) }

type discardLogger struct{}

func (discardLogger) Printf(string, ...interface{}) {
	// throwing the line away is the whole point
}

// DiscardLogger throws away everything the proxy reports.
var DiscardLogger Logger = discardLogger{}

// NewSlogLogger adapts a *slog.Logger, which is what a program embedding this
// package is most likely to already have. Every line is recorded at level.
func NewSlogLogger(logger *slog.Logger, level slog.Level) Logger {
	return LoggerFunc(func(format string, v ...interface{}) {
		logger.Log(context.Background(), level, strings.TrimRight(fmt.Sprintf(format, v...), "\n"))
	})
}

// FileLogger writes to a file, or to stderr when its path is empty, and can
// reopen it in place for logrotate. Reopening in place means nobody has to
// swap the logger of a running proxy while requests are being served.
type FileLogger struct {
	path string
	out  *log.Logger

	mu   sync.Mutex
	file *os.File
}

// NewFileLogger logs to path, or to stderr when path is empty.
func NewFileLogger(path string) (*FileLogger, error) {
	logger := &FileLogger{
		path: path,
		out:  log.New(os.Stderr, "", log.LstdFlags),
	}

	if path == "" {
		return logger, nil
	}

	if err := logger.Reopen(); err != nil {
		return nil, err
	}

	return logger, nil
}

// Printf implements Logger.
func (l *FileLogger) Printf(format string, v ...interface{}) {
	l.out.Printf(format, v...)
}

// Reopen points the logger at a freshly opened file. log.Logger serializes
// writes with the change of destination, so concurrent Printf calls either
// reach the old file before it is closed or the new one.
func (l *FileLogger) Reopen() error {
	if l.path == "" {
		return nil
	}

	file, err := openLogFile(l.path)
	if err != nil {
		return err
	}

	l.out.SetOutput(file)

	l.mu.Lock()
	previous := l.file
	l.file = file
	l.mu.Unlock()

	if previous != nil {
		return previous.Close()
	}

	return nil
}

// Close releases the file, after which the logger writes to stderr again.
func (l *FileLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file == nil {
		return nil
	}

	l.out.SetOutput(os.Stderr)
	file := l.file
	l.file = nil

	return file.Close()
}

// AccessEntry is one line of the access log: a request that was served, or a
// tunnel that was opened.
type AccessEntry struct {
	Time          time.Time
	RemoteAddr    string
	Method        string
	URL           string
	StatusCode    int
	ContentLength int64
	// User is the authenticated user, empty when the request was not
	// authenticated.
	User string
	Err  error
}

// AccessLogger records the requests the proxy serves. It is called from the
// goroutine serving the request, so an implementation that can block should
// hand the entry to a writer of its own, the way FileAccessLogger does.
type AccessLogger interface {
	LogAccess(*AccessEntry)
}

// AccessLoggerFunc adapts a function to AccessLogger.
type AccessLoggerFunc func(*AccessEntry)

// LogAccess implements AccessLogger.
func (f AccessLoggerFunc) LogAccess(entry *AccessEntry) { f(entry) }

// String formats the entry the way microproxy has always written its access
// log: fields separated by spaces, "-" for the ones a request did not carry.
func (e *AccessEntry) String() string {
	status := "-"
	if e.StatusCode != 0 {
		status = strconv.Itoa(e.StatusCode)
	}

	length := "-"
	if e.ContentLength >= 0 && e.StatusCode != 0 {
		length = strconv.FormatInt(e.ContentLength, 10)
	}

	return fmt.Sprintf("%v %v %v %v %v %v %v",
		e.Time.Format(time.RFC3339),
		orDash(e.RemoteAddr),
		orDash(e.Method),
		orDash(e.URL),
		status,
		length,
		orDash(e.User))
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}

	return s
}

// accessLogBuffer is how many entries may be waiting to be written before the
// requests producing them start waiting too.
const accessLogBuffer = 256

// FileAccessLogger writes the access log to a file from a goroutine of its own,
// so that a slow disk delays the writer rather than the requests.
type FileAccessLogger struct {
	path    string
	entries chan *AccessEntry
	done    chan error

	// mu guards closed, and is held for reading by every LogAccess call so
	// that Close can't shut the channel while an entry is being sent on it.
	mu     sync.RWMutex
	closed bool
}

// NewFileAccessLogger appends the access log to path.
func NewFileAccessLogger(path string) (*FileAccessLogger, error) {
	file, err := openLogFile(path)
	if err != nil {
		return nil, err
	}

	logger := &FileAccessLogger{
		path:    path,
		entries: make(chan *AccessEntry, accessLogBuffer),
		done:    make(chan error, 1),
	}

	go logger.run(file)

	return logger, nil
}

func (l *FileAccessLogger) run(file *os.File) {
	for entry := range l.entries {
		if entry == nil {
			// a reopen request, see Reopen
			reopened, err := openLogFile(l.path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "couldn't reopen access log %v: %v\n", l.path, err)
				continue
			}

			_ = file.Close()
			file = reopened

			continue
		}

		if _, err := file.WriteString(entry.String() + "\n"); err != nil {
			fmt.Fprintf(os.Stderr, "couldn't write to access log %v: %v\n", l.path, err)
		}
	}

	l.done <- file.Close()
}

// LogAccess implements AccessLogger. It hands the entry to the writing
// goroutine, and discards it once the logger has been closed.
func (l *FileAccessLogger) LogAccess(entry *AccessEntry) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.closed {
		return
	}

	l.entries <- entry
}

// Reopen makes the logger write to a freshly opened file, for logrotate.
func (l *FileAccessLogger) Reopen() error {
	l.LogAccess(nil)

	return nil
}

// Close flushes the entries already handed over and releases the file. Entries
// submitted afterwards are discarded rather than panicking on a closed channel.
func (l *FileAccessLogger) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()

		return nil
	}
	l.closed = true
	close(l.entries)
	l.mu.Unlock()

	return <-l.done
}

func openLogFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
}

// logResponse records a request that got a response, which is every request but
// the tunnelled ones.
func (s *Server) logResponse(resp *http.Response, ctx *goproxy.ProxyCtx) {
	if s.access == nil {
		return
	}

	entry := &AccessEntry{
		Time:          time.Now(),
		User:          authenticatedUser(ctx),
		ContentLength: -1,
	}

	if ctx != nil {
		entry.Err = ctx.Error
	}

	if resp != nil {
		entry.StatusCode = resp.StatusCode
		entry.ContentLength = resp.ContentLength

		if resp.Request != nil {
			entry.RemoteAddr = resp.Request.RemoteAddr
			entry.Method = resp.Request.Method
			entry.URL = urlString(resp.Request)
		}
	}

	s.access.LogAccess(entry)
}

// logConnect records a tunnel being opened. Tunnelled traffic never reaches the
// response handlers, so this is the only place an HTTPS request can be logged.
func (s *Server) logConnect(ctx *goproxy.ProxyCtx) {
	if s.access == nil {
		return
	}

	entry := &AccessEntry{
		Time:          time.Now(),
		User:          authenticatedUser(ctx),
		ContentLength: -1,
	}

	if ctx == nil {
		s.access.LogAccess(entry)

		return
	}

	entry.Err = ctx.Error

	if ctx.Req != nil {
		entry.RemoteAddr = ctx.Req.RemoteAddr
		entry.Method = ctx.Req.Method
		entry.URL = urlString(ctx.Req)
	}

	if ctx.Resp != nil {
		entry.StatusCode = ctx.Resp.StatusCode
		entry.ContentLength = ctx.Resp.ContentLength
	}

	s.access.LogAccess(entry)
}

func urlString(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}

	return req.URL.String()
}

// authenticatedUser is the user the request authenticated as, which the
// authentication handlers leave in the goproxy context.
func authenticatedUser(ctx *goproxy.ProxyCtx) string {
	if ctx == nil {
		return ""
	}

	user, _ := ctx.UserData.(string)

	return user
}

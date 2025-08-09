package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

// Config via env
// SRG_LISTEN_ADDR: default :8080
// SRG_AUTH_KEYS_PATH: default /etc/ssh/authorized_keys
// SRG_EXEC_TIMEOUT: default 120s

const (
	defaultListenAddr   = ":8080"
	defaultAuthKeysPath = "/etc/ssh/authorized_keys"
	defaultExecTimeout  = 120 * time.Second
)

// ExecRequest represents the POST payload for /api/v1/exec
// stdin may be a plain string or base64 if stdin_b64 is true.
// If timeout_seconds is provided, it overrides the default per-request.

type ExecRequest struct {
	Cmd            string   `json:"cmd"`
	Args           []string `json:"args"`
	Stdin          string   `json:"stdin,omitempty"`
	StdinB64       bool     `json:"stdin_b64,omitempty"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty"`
	WorkDir        string   `json:"workdir,omitempty"`
	Env            []string `json:"env,omitempty"` // KEY=VALUE entries
}

// jobsPeekHandler implements a two-phase guidance: given current stdout/stderr offsets,
// it returns what the client should do next: read_stdout, read_stderr, write_stdin, or exit_status.
// If multiple are possible, priority is stdout > stderr > exit_status > write_stdin.
// Request JSON: { "job_id": "...", "stdout_offset": 0, "stderr_offset": 0 }
// Response JSON: {
//   "job_id":"...", "state":"running|exited|canceled|failed",
//   "stdout_size":N, "stderr_size":N, "exit_code":int,
//   "timed_out":bool, "stdin_open":bool,
//   "next_action":"read_stdout|read_stderr|exit_status|write_stdin"
// }
func jobsPeekHandler(jm *JobManager) http.Handler {
    type reqT struct {
        JobID        string `json:"job_id"`
        StdoutOffset int    `json:"stdout_offset"`
        StderrOffset int    `json:"stderr_offset"`
    }
    type respT struct {
        JobID      string `json:"job_id"`
        State      string `json:"state"`
        StdoutSize int    `json:"stdout_size"`
        StderrSize int    `json:"stderr_size"`
        ExitCode   int    `json:"exit_code"`
        TimedOut   bool   `json:"timed_out"`
        StdinOpen  bool   `json:"stdin_open"`
        NextAction string `json:"next_action"`
    }
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
            return
        }
        var body reqT
        if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.JobID) == "" {
            http.Error(w, "invalid json or missing job_id", http.StatusBadRequest)
            return
        }
        j, ok := jm.Get(body.JobID)
        if !ok {
            http.Error(w, "job not found", http.StatusNotFound)
            return
        }
        j.mu.RLock()
        defer j.mu.RUnlock()
        sb := j.stdoutBuf.Len()
        eb := j.stderrBuf.Len()
        // Heuristics for next action
        next := "write_stdin"
        if body.StdoutOffset < sb {
            next = "read_stdout"
        } else if body.StderrOffset < eb {
            next = "read_stderr"
        } else if j.state != "running" {
            next = "exit_status"
        } else {
            // running and no new output vs offsets
            // if stdin writer exists, allow writing
            if !j.stdinOpen {
                next = "exit_status"
            }
        }
        w.Header().Set("Content-Type", "application/json")
        _ = json.NewEncoder(w).Encode(respT{
            JobID:      j.id,
            State:      j.state,
            StdoutSize: sb,
            StderrSize: eb,
            ExitCode:   j.exitCode,
            TimedOut:   j.timedOut,
            StdinOpen:  j.stdinOpen,
            NextAction: next,
        })
    })
}

// execPipeHandler allows unknown-length stdin by streaming the HTTP request body directly to the child process stdin.
// Usage: POST /api/v1/exec/pipe?cmd=...&arg=...&timeout_seconds=...
// Body: raw stdin (any content-type). Optional headers: X-Workdir, X-Env (comma-separated KEY=VALUE pairs)
func execPipeHandler(defaultTimeout time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		q := r.URL.Query()
		cmdName := strings.TrimSpace(q.Get("cmd"))
		if cmdName == "" {
			http.Error(w, "cmd query param is required", http.StatusBadRequest)
			return
		}
		args := q["arg"]

		timeout := defaultTimeout
		if ts := q.Get("timeout_seconds"); ts != "" {
			if v, err := time.ParseDuration(ts + "s"); err == nil {
				timeout = v
			}
		}

		var ctx context.Context
		var cancel context.CancelFunc
		if timeout <= 0 {
			ctx, cancel = context.WithCancel(r.Context())
		} else {
			ctx, cancel = context.WithTimeout(r.Context(), timeout)
		}
		defer cancel()

		cmd := exec.CommandContext(ctx, cmdName, args...)

		if wd := r.Header.Get("X-Workdir"); wd != "" {
			cmd.Dir = wd
		}
		if envHdr := r.Header.Get("X-Env"); envHdr != "" {
			// Accept comma-separated KEY=VALUE entries
			parts := strings.Split(envHdr, ",")
			cleaned := make([]string, 0, len(parts))
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p != "" {
					cleaned = append(cleaned, p)
				}
			}
			if len(cleaned) > 0 {
				cmd.Env = append(os.Environ(), cleaned...)
			}
		}

		// Directly pipe request body to child stdin; ensure body closed after run
		pr, pw := io.Pipe()
		go func() {
			defer pw.Close()
			_, _ = io.Copy(pw, r.Body)
		}()
		defer r.Body.Close()

		var outBuf, errBuf bytes.Buffer
		cmd.Stdin = pr
		cmd.Stdout = &outBuf
		cmd.Stderr = &errBuf

		start := time.Now()
		var exitCode int
		timedOut := false
		err := cmd.Run()
		dur := time.Since(start)

		if ctx.Err() == context.DeadlineExceeded {
			timedOut = true
		}
		if err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				if ws, ok := ee.Sys().(syscall.WaitStatus); ok {
					exitCode = ws.ExitStatus()
				}
			} else {
				exitCode = 127
			}
		} else {
			exitCode = 0
		}

		resp := ExecResponse{
			Stdout:     outBuf.String(),
			Stderr:     errBuf.String(),
			ExitCode:   exitCode,
			TimedOut:   timedOut,
			DurationMs: dur.Milliseconds(),
			StdoutB64:  false,
			StderrB64:  false,
		}

		w.Header().Set("Content-Type", "application/json")
		status := http.StatusOK
		if timedOut {
			status = http.StatusRequestTimeout
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(resp)
	})
}

type ExecResponse struct {
	Stdout      string `json:"stdout"`
	Stderr      string `json:"stderr"`
	ExitCode    int    `json:"exit_code"`
	TimedOut    bool   `json:"timed_out"`
	DurationMs  int64  `json:"duration_ms"`
	StdoutB64   bool   `json:"stdout_b64"`
	StderrB64   bool   `json:"stderr_b64"`
}

func main() {
    // Flags
    flagListen := flag.String("listen", "", "listen address (e.g. :8080)")
    flagAuth := flag.String("auth-keys", "", "path to authorized_keys file")
    flagTimeout := flag.String("exec-timeout", "", "default exec timeout (e.g. 120s, 0s to disable)")
    flagConfig := flag.String("config", "", "path to sshrest.conf (env-style)")
    flagSetup := flag.Bool("setup", false, "write default config file and exit")
    flagHelp := flag.Bool("help", false, "show help and exit")

    flag.Usage = func() {
        fmt.Fprintf(os.Stderr, "shellrest-go: Async SSH-like REST API server\n")
        fmt.Fprintf(os.Stderr, "Usage: %s [flags]\n\n", os.Args[0])
        fmt.Fprintf(os.Stderr, "Flags:\n")
        flag.PrintDefaults()
        fmt.Fprintf(os.Stderr, "\nEnvironment variables (overridden by flags):\n")
        fmt.Fprintf(os.Stderr, "  SRG_LISTEN_ADDR     (default %s)\n", defaultListenAddr)
        fmt.Fprintf(os.Stderr, "  SRG_AUTH_KEYS_PATH  (default %s)\n", defaultAuthKeysPath)
        fmt.Fprintf(os.Stderr, "  SRG_EXEC_TIMEOUT    (default %s)\n", defaultExecTimeout)
        fmt.Fprintf(os.Stderr, "Config file (env-style): %s (or --config)\n", defaultConfigPath())
    }
    flag.Parse()

    if *flagHelp {
        flag.Usage()
        return
    }

    // Load config file before reading env
    cfgPath := *flagConfig
    if cfgPath == "" {
        cfgPath = defaultConfigPath()
    }
    if _, err := os.Stat(cfgPath); err == nil {
        _ = loadEnvFile(cfgPath)
    } else if *flagSetup {
        // ensure directory and write default config
        dir := filepath.Dir(cfgPath)
        _ = os.MkdirAll(dir, 0o755)
        _ = os.WriteFile(cfgPath, []byte("# shellrest-go config\nSRG_LISTEN_ADDR=:8080\nSRG_AUTH_KEYS_PATH=/etc/ssh/authorized_keys\nSRG_EXEC_TIMEOUT=120s\n"), 0o644)
        fmt.Printf("wrote default config at %s\n", cfgPath)
        return
    }
    if *flagSetup {
        // If config existed, just report path and exit
        fmt.Printf("config present at %s\n", cfgPath)
        return
    }

    listenAddr := getenv("SRG_LISTEN_ADDR", defaultListenAddr)
    authPath := getenv("SRG_AUTH_KEYS_PATH", defaultAuthKeysPath)
    defaultTimeout := getenvDuration("SRG_EXEC_TIMEOUT", defaultExecTimeout)

    // Flags override env if provided
    if *flagListen != "" { listenAddr = *flagListen }
    if *flagAuth != "" { authPath = *flagAuth }
    if *flagTimeout != "" {
        if d, err := time.ParseDuration(*flagTimeout); err == nil { defaultTimeout = d }
    }

	validTokens, err := loadValidBearerTokens(authPath)
	if err != nil {
		log.Fatalf("failed to load authorized keys from %s: %v", authPath, err)
	}
	log.Printf("Loaded %d ed25519 public keys from %s", len(validTokens), authPath)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("/api/v1/exec", withAuth(validTokens, execHandler(defaultTimeout)))
	mux.Handle("/api/v1/exec/pipe", withAuth(validTokens, execPipeHandler(defaultTimeout)))

	// Async job orchestration endpoints (POST-only)
	jm := NewJobManager()
	mux.Handle("/api/v1/jobs/start", withAuth(validTokens, jobsStartHandler(jm, defaultTimeout)))
	mux.Handle("/api/v1/jobs/status", withAuth(validTokens, jobsStatusHandler(jm)))
	mux.Handle("/api/v1/jobs/logs", withAuth(validTokens, jobsLogsHandler(jm)))
	mux.Handle("/api/v1/jobs/stdin", withAuth(validTokens, jobsStdinHandler(jm)))
	mux.Handle("/api/v1/jobs/cancel", withAuth(validTokens, jobsCancelHandler(jm)))
	mux.Handle("/api/v1/jobs/peek", withAuth(validTokens, jobsPeekHandler(jm)))

	// Filesystem endpoints (UTF-8, POST-only)
	mux.Handle("/api/v1/fs/write_file", withAuth(validTokens, fsWriteFileHandler()))
	mux.Handle("/api/v1/fs/read_file", withAuth(validTokens, fsReadFileHandler()))

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           logMiddleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
		// Do not set ReadTimeout to avoid cutting off long request bodies (streaming stdin)
		// ReadTimeout:    0,
		WriteTimeout:      0, // allow long responses
		IdleTimeout:       5 * time.Minute,
	}

	go func() {
		log.Printf("Starting server on %s", listenAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	<-stop
	log.Printf("Shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

// withAuth enforces Bearer token auth. The token must equal the hex-encoded SHA-256
// of the decoded ssh-ed25519 public key bytes found in authorized_keys.
func withAuth(validTokens map[string]struct{}, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ah := r.Header.Get("Authorization")
		if ah == "" || !strings.HasPrefix(strings.ToLower(ah), "bearer ") {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		token := strings.TrimSpace(ah[len("Bearer "):])
		if _, ok := validTokens[token]; !ok {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func execHandler(defaultTimeout time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req ExecRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("invalid json: %v", err), http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.Cmd) == "" {
			http.Error(w, "cmd is required", http.StatusBadRequest)
			return
		}

		stdinBytes := []byte(req.Stdin)
		if req.StdinB64 && req.Stdin != "" {
			b, err := base64.StdEncoding.DecodeString(req.Stdin)
			if err != nil {
				http.Error(w, fmt.Sprintf("invalid stdin base64: %v", err), http.StatusBadRequest)
				return
			}
			stdinBytes = b
		}

		timeout := defaultTimeout
		// If provided, even 0 means disable timeout
		if req.TimeoutSeconds != 0 {
			timeout = time.Duration(req.TimeoutSeconds) * time.Second
		}

		var ctx context.Context
		var cancel context.CancelFunc
		if timeout <= 0 {
			ctx, cancel = context.WithCancel(r.Context())
		} else {
			ctx, cancel = context.WithTimeout(r.Context(), timeout)
		}
		defer cancel()

		cmd := exec.CommandContext(ctx, req.Cmd, req.Args...)
		if req.WorkDir != "" {
			cmd.Dir = req.WorkDir
		}
		if len(req.Env) > 0 {
			cmd.Env = append(os.Environ(), req.Env...)
		}

		var outBuf, errBuf bytes.Buffer
		cmd.Stdin = bytes.NewReader(stdinBytes)
		cmd.Stdout = &outBuf
		cmd.Stderr = &errBuf

		start := time.Now()
		var exitCode int
		timedOut := false
		err := cmd.Run()
		dur := time.Since(start)

		if ctx.Err() == context.DeadlineExceeded {
			timedOut = true
		}
		if err != nil {
			// Extract exit code if possible
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				if ws, ok := ee.Sys().(syscall.WaitStatus); ok {
					exitCode = ws.ExitStatus()
				}
			} else {
				// Non-exit error (e.g., command not found)
				exitCode = 127
			}
		} else {
			exitCode = 0
		}

		resp := ExecResponse{
			Stdout:     outBuf.String(),
			Stderr:     errBuf.String(),
			ExitCode:   exitCode,
			TimedOut:   timedOut,
			DurationMs: dur.Milliseconds(),
			StdoutB64:  false,
			StderrB64:  false,
		}

		w.Header().Set("Content-Type", "application/json")
		status := http.StatusOK
		// Return 408 if timed out; otherwise 200 even on non-zero exit codes.
		if timedOut {
			status = http.StatusRequestTimeout
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// ===================== Async Jobs =====================

type Job struct {
    id        string
    cmd       *exec.Cmd
    ctx       context.Context
    cancel    context.CancelFunc
    stdinW    *io.PipeWriter
    stdinOpen bool
    stdoutBuf bytes.Buffer
    stderrBuf bytes.Buffer
    mu        sync.RWMutex
    startAt   time.Time
    endAt     time.Time
    exitCode  int
    timedOut  bool
    state     string // running|exited|canceled|failed
    done      chan struct{}
}

type JobManager struct {
    mu   sync.RWMutex
    jobs map[string]*Job
}

func NewJobManager() *JobManager {
    return &JobManager{jobs: make(map[string]*Job)}
}

func (jm *JobManager) Add(j *Job) {
    jm.mu.Lock()
    defer jm.mu.Unlock()
    jm.jobs[j.id] = j
}

func (jm *JobManager) Get(id string) (*Job, bool) {
    jm.mu.RLock()
    defer jm.mu.RUnlock()
    j, ok := jm.jobs[id]
    return j, ok
}

func (jm *JobManager) Remove(id string) {
    jm.mu.Lock()
    defer jm.mu.Unlock()
    delete(jm.jobs, id)
}

func genJobID() string {
    b := make([]byte, 16)
    if _, err := rand.Read(b); err != nil {
        ts := time.Now().UnixNano()
        return fmt.Sprintf("j%x", ts)
    }
    return hex.EncodeToString(b)
}

type JobStartRequest struct {
    Cmd            string   `json:"cmd"`
    Args           []string `json:"args"`
    Stdin          string   `json:"stdin,omitempty"`
    StdinB64       bool     `json:"stdin_b64,omitempty"`
    TimeoutSeconds int      `json:"timeout_seconds,omitempty"`
    WorkDir        string   `json:"workdir,omitempty"`
    Env            []string `json:"env,omitempty"`
}

type JobStartResponse struct {
    JobID string `json:"job_id"`
}

type JobStatusResponse struct {
    JobID      string `json:"job_id"`
    State      string `json:"state"`
    ExitCode   int    `json:"exit_code"`
    TimedOut   bool   `json:"timed_out"`
    StartTime  int64  `json:"start_time_unix_ms"`
    EndTime    int64  `json:"end_time_unix_ms"`
    DurationMs int64  `json:"duration_ms"`
    StdoutSize int    `json:"stdout_size"`
    StderrSize int    `json:"stderr_size"`
}

type JobLogsResponse struct {
    JobID        string `json:"job_id"`
    Stdout       string `json:"stdout"`
    Stderr       string `json:"stderr"`
    StdoutOffset int    `json:"stdout_offset"`
    StderrOffset int    `json:"stderr_offset"`
    StdoutNext   int    `json:"stdout_next_offset"`
    StderrNext   int    `json:"stderr_next_offset"`
    Done         bool   `json:"done"`
}

func jobsStartHandler(jm *JobManager, defaultTimeout time.Duration) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
            return
        }
        var req JobStartRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, fmt.Sprintf("invalid json: %v", err), http.StatusBadRequest)
            return
        }
        if strings.TrimSpace(req.Cmd) == "" {
            http.Error(w, "cmd is required", http.StatusBadRequest)
            return
        }

        timeout := defaultTimeout
        if req.TimeoutSeconds != 0 {
            timeout = time.Duration(req.TimeoutSeconds) * time.Second
        }

        var ctx context.Context
        var cancel context.CancelFunc
        // Important: do not derive from the request context, since it is canceled
        // when the HTTP request returns. Async jobs must outlive the start call.
        if timeout <= 0 {
            ctx, cancel = context.WithCancel(context.Background())
        } else {
            ctx, cancel = context.WithTimeout(context.Background(), timeout)
        }

        cmd := exec.CommandContext(ctx, req.Cmd, req.Args...)
        if req.WorkDir != "" {
            cmd.Dir = req.WorkDir
        }
        if len(req.Env) > 0 {
            cmd.Env = append(os.Environ(), req.Env...)
        }

        pr, pw := io.Pipe()
        cmd.Stdin = pr

        j := &Job{
            id:      genJobID(),
            cmd:     cmd,
            ctx:     ctx,
            cancel:  cancel,
            stdinW:  pw,
            stdinOpen: true,
            startAt: time.Now(),
            state:   "running",
            done:    make(chan struct{}),
        }
        j.cmd.Stdout = &j.stdoutBuf
        j.cmd.Stderr = &j.stderrBuf

        if req.Stdin != "" {
            var b []byte
            if req.StdinB64 {
                dec, err := base64.StdEncoding.DecodeString(req.Stdin)
                if err != nil {
                    http.Error(w, fmt.Sprintf("invalid stdin base64: %v", err), http.StatusBadRequest)
                    cancel()
                    return
                }
                b = dec
            } else {
                b = []byte(req.Stdin)
            }
            go func() { _, _ = j.stdinW.Write(b) }()
        }

        if err := j.cmd.Start(); err != nil {
            cancel()
            http.Error(w, fmt.Sprintf("failed to start: %v", err), http.StatusInternalServerError)
            return
        }

        go func() {
            err := j.cmd.Wait()
            j.mu.Lock()
            defer j.mu.Unlock()
            j.endAt = time.Now()
            // Mark stdin closed on process exit
            if j.stdinOpen {
                j.stdinOpen = false
                j.stdinW = nil
            }
            if j.ctx.Err() == context.DeadlineExceeded {
                j.timedOut = true
            }
            if err != nil {
                var ee *exec.ExitError
                if errors.As(err, &ee) {
                    if ws, ok := ee.Sys().(syscall.WaitStatus); ok {
                        j.exitCode = ws.ExitStatus()
                    } else {
                        j.exitCode = 127
                    }
                } else {
                    j.exitCode = 127
                }
                if j.state == "running" {
                    j.state = "exited"
                }
            } else {
                j.exitCode = 0
                j.state = "exited"
            }
            close(j.done)
        }()

        jm.Add(j)
        w.Header().Set("Content-Type", "application/json")
        _ = json.NewEncoder(w).Encode(JobStartResponse{JobID: j.id})
    })
}

func jobsStatusHandler(jm *JobManager) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
            return
        }
        var body struct{ JobID string `json:"job_id"` }
        if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.JobID) == "" {
            http.Error(w, "invalid json or missing job_id", http.StatusBadRequest)
            return
        }
        j, ok := jm.Get(body.JobID)
        if !ok {
            http.Error(w, "job not found", http.StatusNotFound)
            return
        }
        j.mu.RLock()
        defer j.mu.RUnlock()
        dur := int64(0)
        endMs := int64(0)
        if !j.startAt.IsZero() {
            end := j.endAt
            if end.IsZero() {
                end = time.Now()
            }
            dur = end.Sub(j.startAt).Milliseconds()
            if !j.endAt.IsZero() {
                endMs = j.endAt.UnixMilli()
            }
        }
        resp := JobStatusResponse{
            JobID:      j.id,
            State:      j.state,
            ExitCode:   j.exitCode,
            TimedOut:   j.timedOut,
            StartTime:  j.startAt.UnixMilli(),
            EndTime:    endMs,
            DurationMs: dur,
            StdoutSize: j.stdoutBuf.Len(),
            StderrSize: j.stderrBuf.Len(),
        }
        w.Header().Set("Content-Type", "application/json")
        _ = json.NewEncoder(w).Encode(resp)
    })
}

func jobsLogsHandler(jm *JobManager) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
            return
        }
        var jobID string
        var so, eo int
        if r.Header.Get("Content-Type") == "application/json" {
            var body struct {
                JobID        string `json:"job_id"`
                StdoutOffset int    `json:"stdout_offset"`
                StderrOffset int    `json:"stderr_offset"`
            }
            if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
                http.Error(w, "invalid json", http.StatusBadRequest)
                return
            }
            jobID = body.JobID
            so = body.StdoutOffset
            eo = body.StderrOffset
        } else {
            jobID = r.URL.Query().Get("job_id")
            so, _ = strconv.Atoi(r.URL.Query().Get("stdout_offset"))
            eo, _ = strconv.Atoi(r.URL.Query().Get("stderr_offset"))
        }
        if strings.TrimSpace(jobID) == "" {
            http.Error(w, "missing job_id", http.StatusBadRequest)
            return
        }
        j, ok := jm.Get(jobID)
        if !ok {
            http.Error(w, "job not found", http.StatusNotFound)
            return
        }
        j.mu.RLock()
        defer j.mu.RUnlock()
        if so < 0 { so = 0 }
        if eo < 0 { eo = 0 }
        sb := j.stdoutBuf.Bytes()
        eb := j.stderrBuf.Bytes()
        if so > len(sb) { so = len(sb) }
        if eo > len(eb) { eo = len(eb) }
        stdout := string(sb[so:])
        stderr := string(eb[eo:])
        resp := JobLogsResponse{
            JobID:        j.id,
            Stdout:       stdout,
            Stderr:       stderr,
            StdoutOffset: so,
            StderrOffset: eo,
            StdoutNext:   len(sb),
            StderrNext:   len(eb),
            Done:         j.state != "running",
        }
        w.Header().Set("Content-Type", "application/json")
        _ = json.NewEncoder(w).Encode(resp)
    })
}

func jobsStdinHandler(jm *JobManager) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
            return
        }
        jobID := r.URL.Query().Get("job_id")
        if strings.TrimSpace(jobID) == "" {
            http.Error(w, "missing job_id", http.StatusBadRequest)
            return
        }
        j, ok := jm.Get(jobID)
        if !ok {
            http.Error(w, "job not found", http.StatusNotFound)
            return
        }
        j.mu.RLock()
        sw := j.stdinW
        open := j.stdinOpen
        j.mu.RUnlock()
        if sw == nil || !open {
            http.Error(w, "stdin closed", http.StatusConflict)
            return
        }
        closeAfter := r.URL.Query().Get("close") == "1"
        n, err := io.Copy(sw, r.Body)
        _ = r.Body.Close()
        if err != nil {
            http.Error(w, fmt.Sprintf("stdin write error: %v", err), http.StatusInternalServerError)
            return
        }
        if closeAfter {
            _ = sw.Close()
            j.mu.Lock()
            j.stdinOpen = false
            j.stdinW = nil
            j.mu.Unlock()
        }
        w.Header().Set("Content-Type", "application/json")
        _ = json.NewEncoder(w).Encode(map[string]any{"job_id": jobID, "written": n, "closed": closeAfter})
    })
}

func jobsCancelHandler(jm *JobManager) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
            return
        }
        var body struct{ JobID string `json:"job_id"` }
        if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.JobID) == "" {
            http.Error(w, "invalid json or missing job_id", http.StatusBadRequest)
            return
        }
        j, ok := jm.Get(body.JobID)
        if !ok {
            http.Error(w, "job not found", http.StatusNotFound)
            return
        }
        if j.cmd.Process != nil {
            _ = j.cmd.Process.Signal(syscall.SIGTERM)
        }
        select {
        case <-j.done:
        case <-time.After(5 * time.Second):
            if j.cmd.Process != nil {
                _ = j.cmd.Process.Kill()
            }
        }
        j.mu.Lock()
        if j.state == "running" {
            j.state = "canceled"
        }
        j.mu.Unlock()
        w.Header().Set("Content-Type", "application/json")
        _ = json.NewEncoder(w).Encode(map[string]any{"job_id": j.id, "state": j.state})
    })
}

// ===================== Filesystem (UTF-8) =====================

type fsWriteReq struct {
    Path    string `json:"path"`
    Content string `json:"content"`
}

type fsWriteResp struct {
    Path         string `json:"path"`
    BytesWritten int    `json:"bytes_written"`
}

func fsWriteFileHandler() http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
            return
        }
        var req fsWriteReq
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, fmt.Sprintf("invalid json: %v", err), http.StatusBadRequest)
            return
        }
        if strings.TrimSpace(req.Path) == "" {
            http.Error(w, "path is required", http.StatusBadRequest)
            return
        }
        clean := filepath.Clean(req.Path)
        dir := filepath.Dir(clean)
        if dir != "." && dir != "" {
            if err := os.MkdirAll(dir, 0o755); err != nil {
                http.Error(w, fmt.Sprintf("mkdir: %v", err), http.StatusInternalServerError)
                return
            }
        }
        b := []byte(req.Content)
        if err := os.WriteFile(clean, b, 0o644); err != nil {
            http.Error(w, fmt.Sprintf("write file: %v", err), http.StatusInternalServerError)
            return
        }
        w.Header().Set("Content-Type", "application/json")
        _ = json.NewEncoder(w).Encode(fsWriteResp{Path: clean, BytesWritten: len(b)})
    })
}

type fsReadReq struct {
    Path string `json:"path"`
}

type fsReadResp struct {
    Path    string `json:"path"`
    Content string `json:"content"`
    Size    int    `json:"size"`
}

func fsReadFileHandler() http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
            return
        }
        var req fsReadReq
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, fmt.Sprintf("invalid json: %v", err), http.StatusBadRequest)
            return
        }
        if strings.TrimSpace(req.Path) == "" {
            http.Error(w, "path is required", http.StatusBadRequest)
            return
        }
        clean := filepath.Clean(req.Path)
        data, err := os.ReadFile(clean)
        if err != nil {
            if os.IsNotExist(err) {
                http.Error(w, "file not found", http.StatusNotFound)
                return
            }
            http.Error(w, fmt.Sprintf("read file: %v", err), http.StatusInternalServerError)
            return
        }
        // UTF-8 response requirement. If not valid UTF-8, reject.
        if !utf8.Valid(data) {
            http.Error(w, "file is not valid UTF-8", http.StatusUnsupportedMediaType)
            return
        }
        w.Header().Set("Content-Type", "application/json")
        _ = json.NewEncoder(w).Encode(fsReadResp{Path: clean, Content: string(data), Size: len(data)})
    })
}

// loadValidBearerTokens parses authorized_keys and returns a set of valid tokens.
// A valid token is hex(SHA256(decoded_base64_key_bytes)) for any ssh-ed25519 key.
func loadValidBearerTokens(path string) (map[string]struct{}, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	tokens := make(map[string]struct{})
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024) // allow long lines
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// authorized_keys format: [options] <keytype> <base64> [comment]
		// Options are a comma-separated list inside quotes or not; we'll split by spaces and pick first token that equals an ssh-* type
		parts := splitAuthorizedKeysLine(line)
		if len(parts) < 2 {
			continue
		}
		keyType := parts[0]
		keyB64 := parts[1]
		if keyType != "ssh-ed25519" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(keyB64)
		if err != nil {
			continue
		}
		h := sha256.Sum256(decoded)
		tokens[hex.EncodeToString(h[:])] = struct{}{}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return tokens, nil
}

// splitAuthorizedKeysLine tries to extract keyType and key data from a line which may start with options.
func splitAuthorizedKeysLine(line string) []string {
	// Simplistic split: tokens by whitespace, but if the first token contains an '=' or starts with 'command=' or options list, skip until we hit 'ssh-*'
	toks := strings.Fields(line)
	for i, t := range toks {
		if strings.HasPrefix(t, "ssh-") {
			return toks[i:]
		}
	}
	return toks
}

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s from %s", r.Method, r.URL.Path, time.Since(start), r.RemoteAddr)
	})
}

// loadEnvFile loads KEY=VALUE lines into the environment if the variable is not already set.
// Lines beginning with # are comments. Blank lines are ignored.
func loadEnvFile(path string) error {
    f, err := os.Open(filepath.Clean(path))
    if err != nil {
        return err
    }
    defer f.Close()
    s := bufio.NewScanner(f)
    for s.Scan() {
        line := strings.TrimSpace(s.Text())
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }
        eq := strings.IndexByte(line, '=')
        if eq <= 0 { // require KEY=...
            continue
        }
        key := strings.TrimSpace(line[:eq])
        val := strings.TrimSpace(line[eq+1:])
        if os.Getenv(key) == "" { // do not overwrite existing env
            _ = os.Setenv(key, val)
        }
    }
    return s.Err()
}

func defaultConfigPath() string {
    if os.Geteuid() == 0 {
        return "/etc/shellrest/sshrest.conf"
    }
    home, _ := os.UserHomeDir()
    if home == "" {
        return "./sshrest.conf"
    }
    return filepath.Join(home, ".config", "shellrest", "sshrest.conf")
}

func getenv(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

func getenvDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	return def
}

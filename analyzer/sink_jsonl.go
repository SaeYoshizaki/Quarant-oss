package analyzer

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// jsonlFlushInterval bounds how long a written line may wait in the buffer,
// so that a live viewer reading the file sees it promptly. Writing every
// line straight to the file took over half of the analysis time on busy
// captures.
const jsonlFlushInterval = time.Second

type JSONLSink struct {
	mu        sync.Mutex
	file      *os.File
	buf       *bufio.Writer
	lastFlush time.Time
}

func NewJSONSink(path string) (*JSONLSink, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &JSONLSink{file: f, buf: bufio.NewWriterSize(f, 256*1024), lastFlush: time.Now()}, nil
}

func (s *JSONLSink) Write(event Event) error {
	return s.writeValue(event)
}

func (s *JSONLSink) WriteFlow(flow FlowRecord) error {
	return s.writeValue(flow)
}

func (s *JSONLSink) WriteObservation(observation ObservationRecord) error {
	return s.writeValue(observation)
}

func (s *JSONLSink) writeValue(v any) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}

	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err := s.buf.Write(append(data, '\n')); err != nil {
		return err
	}
	// Wall-clock time here only paces file I/O; it does not enter the
	// analysis.
	if now := time.Now(); now.Sub(s.lastFlush) >= jsonlFlushInterval {
		s.lastFlush = now
		return s.buf.Flush()
	}
	return nil
}

// Flush writes buffered lines to the file.
func (s *JSONLSink) Flush() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	return s.buf.Flush()
}

func (s *JSONLSink) Close() error {
	if s == nil || s.file == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ferr := s.buf.Flush()
	err := s.file.Close()
	s.file = nil
	if ferr != nil {
		return ferr
	}
	return err
}

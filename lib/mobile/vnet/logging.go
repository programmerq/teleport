// Teleport
// Copyright (C) 2026 Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//go:build linux

package vnet

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
)

// Logger is implemented by the Android app so that Go logs reach logcat. A
// gomobile-bound library writes to a file descriptor nobody is reading, so
// without this bridge every log line from lib/vnet is lost.
//
// Level follows log/slog: -4 debug, 0 info, 4 warn, 8 error.
type Logger interface {
	Log(level int, message string)
}

// SetLogger routes all Teleport logging through logger at the given level, and
// is the first thing the app should call. Passing a nil logger restores
// discarding output.
//
// Teleport's package loggers resolve slog.Default() lazily, so this takes
// effect for packages that were initialized before it is called.
func SetLogger(logger Logger, level int) {
	if logger == nil {
		slog.SetDefault(slog.New(slog.DiscardHandler))
		return
	}
	slog.SetDefault(slog.New(&bridgeHandler{
		logger: logger,
		level:  slog.Level(level),
	}))
}

// bridgeHandler is a minimal slog.Handler that renders a record as a single
// line and hands it to the app.
type bridgeHandler struct {
	logger Logger
	level  slog.Level
	attrs  []slog.Attr
	group  string

	// mu serializes calls into the app, which crosses the JNI boundary and is
	// not guaranteed to be goroutine-safe on the Kotlin side.
	mu sync.Mutex
}

func (h *bridgeHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *bridgeHandler) Handle(_ context.Context, record slog.Record) error {
	var sb strings.Builder
	sb.WriteString(record.Message)
	writeAttr := func(attr slog.Attr) bool {
		if attr.Equal(slog.Attr{}) {
			return true
		}
		key := attr.Key
		if h.group != "" {
			key = h.group + "." + key
		}
		fmt.Fprintf(&sb, " %s=%v", key, attr.Value.Resolve().Any())
		return true
	}
	for _, attr := range h.attrs {
		writeAttr(attr)
	}
	record.Attrs(writeAttr)

	h.mu.Lock()
	defer h.mu.Unlock()
	h.logger.Log(int(record.Level), sb.String())
	return nil
}

func (h *bridgeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &bridgeHandler{
		logger: h.logger,
		level:  h.level,
		attrs:  append(append([]slog.Attr{}, h.attrs...), attrs...),
		group:  h.group,
	}
}

func (h *bridgeHandler) WithGroup(name string) slog.Handler {
	group := name
	if h.group != "" {
		group = h.group + "." + name
	}
	return &bridgeHandler{
		logger: h.logger,
		level:  h.level,
		attrs:  append([]slog.Attr{}, h.attrs...),
		group:  group,
	}
}

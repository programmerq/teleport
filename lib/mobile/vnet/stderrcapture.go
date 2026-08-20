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
	"bufio"
	"os"
	"strings"
	"sync"
)

// stderrCaptureMu serializes captures, because swapping os.Stderr is
// process-global. Only one browser-based login may run at a time.
var stderrCaptureMu sync.Mutex

// captureStderrURLs temporarily replaces os.Stderr with a pipe and reports any
// URL written to it on the returned channel.
//
// This exists only because lib/client's SSO redirector reports the URL to open
// by printing it, and captures its writer from os.Stderr when the redirector is
// constructed - deep inside TeleportClient.Login, with no hook to intercept.
// The proper fix is a redirect handler on client.Config; until then this is how
// an app with no terminal learns which URL to open.
//
// The returned function restores os.Stderr and closes the channel. It is safe
// to call more than once.
func captureStderrURLs() (restore func(), urls <-chan string) {
	stderrCaptureMu.Lock()

	found := make(chan string, 4)
	reader, writer, err := os.Pipe()
	if err != nil {
		// Without a pipe there is nothing to capture; the login will still run
		// and the user will simply not get a browser opened for them.
		close(found)
		stderrCaptureMu.Unlock()
		return func() {}, found
	}

	original := os.Stderr
	os.Stderr = writer

	go func() {
		defer close(found)
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			line := scanner.Text()
			// Keep the output visible: the app's log bridge does not cover
			// anything written directly to stderr.
			//nolint:errcheck // best effort tee back to the real stderr
			original.WriteString(line + "\n")
			if url := extractURL(line); url != "" {
				select {
				case found <- url:
				default:
				}
			}
		}
	}()

	var once sync.Once
	return func() {
		once.Do(func() {
			os.Stderr = original
			_ = writer.Close()
			stderrCaptureMu.Unlock()
		})
	}, found
}

// extractURL returns the first http or https URL in line, or an empty string.
func extractURL(line string) string {
	for _, scheme := range []string{"https://", "http://"} {
		idx := strings.Index(line, scheme)
		if idx < 0 {
			continue
		}
		url := line[idx:]
		// The redirector prints the URL last on the line, but trim anything
		// that clearly cannot be part of it.
		if cut := strings.IndexAny(url, " \t\r\n\""); cut >= 0 {
			url = url[:cut]
		}
		return url
	}
	return ""
}

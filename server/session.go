// sshanity/server/session.go
// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2016 Glider Labs. All rights reserved.

// The ssh session handling is a modified version from
// https://github.com/gliderlabs/ssh/blob/master/session.go
// This implementation adds a few handler types and removes a bunch of
// stuff not needed since we do not actually run shells or subsystems.

package server

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/anmitsu/go-shlex"
	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"
)

// maxSigBufSize is how many signals will be buffered
// when there is no signal channel specified
const maxSigBufSize = 128

func DefaultSessionHandler(srv *ssh.Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx ssh.Context) {
	ch, reqs, err := newChan.Accept()
	if err != nil {
		log.Errorf("ssh: could not accept channel: %v", err)
		return
	}
	sess := &session{
		Channel:   ch,
		conn:      conn,
		handler:   srv.Handler,
		ptyCb:     srv.PtyCallback,
		sessReqCb: srv.SessionRequestCallback,
		ctx:       ctx,
		server:    srv,
	}
	sess.handleRequests(reqs)
}

type session struct {
	sync.Mutex
	gossh.Channel
	conn      *gossh.ServerConn
	handler   ssh.Handler
	handled   bool
	exited    bool
	pty       *ssh.Pty
	winch     chan ssh.Window
	env       []string
	ptyCb     ssh.PtyCallback
	sessReqCb ssh.SessionRequestCallback
	rawCmd    string
	subsystem string
	ctx       ssh.Context
	sigCh     chan<- ssh.Signal
	sigBuf    []ssh.Signal
	breakCh   chan<- bool
	server    *ssh.Server
}

func (sess *session) Write(p []byte) (n int, err error) {
	if sess.pty != nil {
		m := len(p)
		// normalize \n to \r\n when pty is accepted.
		// this is a hardcoded shortcut since we don't support terminal modes.
		p = bytes.ReplaceAll(p, []byte{'\n'}, []byte{'\r', '\n'})
		p = bytes.ReplaceAll(p, []byte{'\r', '\r', '\n'}, []byte{'\r', '\n'})
		n, err = sess.Channel.Write(p)
		if n > m {
			n = m
		}
		return
	}
	return sess.Channel.Write(p)
}

func (sess *session) PublicKey() ssh.PublicKey {
	sessionkey := sess.ctx.Value(ssh.ContextKeyPublicKey)
	if sessionkey == nil {
		return nil
	}
	return sessionkey.(ssh.PublicKey)
}

func (sess *session) Permissions() ssh.Permissions {
	// use context permissions because its properly
	// wrapped and easier to dereference
	perms := sess.ctx.Value(ssh.ContextKeyPermissions).(*ssh.Permissions)
	return *perms
}

func (sess *session) Context() ssh.Context {
	return sess.ctx
}

func (sess *session) Exit(code int) error {
	sess.Lock()
	defer sess.Unlock()
	if sess.exited {
		return errors.New("Session.Exit called multiple times")
	}
	sess.exited = true

	status := struct{ Status uint32 }{uint32(code)}
	_, err := sess.SendRequest("exit-status", false, gossh.Marshal(&status))
	if err != nil {
		return err
	}
	return sess.Close()
}

func (sess *session) User() string {
	return sess.conn.User()
}

func (sess *session) RemoteAddr() net.Addr {
	return sess.conn.RemoteAddr()
}

func (sess *session) LocalAddr() net.Addr {
	return sess.conn.LocalAddr()
}

func (sess *session) Environ() []string {
	return append([]string(nil), sess.env...)
}

func (sess *session) RawCommand() string {
	return sess.rawCmd
}

func (sess *session) Command() []string {
	cmd, _ := shlex.Split(sess.rawCmd, true)
	return append([]string(nil), cmd...)
}

func (sess *session) Subsystem() string {
	return sess.subsystem
}

func (sess *session) Pty() (ssh.Pty, <-chan ssh.Window, bool) {
	if sess.pty != nil {
		return *sess.pty, sess.winch, true
	}
	return ssh.Pty{}, sess.winch, false
}

func (sess *session) Signals(c chan<- ssh.Signal) {
	sess.Lock()
	defer sess.Unlock()
	sess.sigCh = c
	if len(sess.sigBuf) > 0 {
		go func() {
			for _, sig := range sess.sigBuf {
				sess.sigCh <- sig
			}
		}()
	}
}

func (sess *session) Break(c chan<- bool) {
	sess.Lock()
	defer sess.Unlock()
	sess.breakCh = c
}

func (sess *session) handleRequests(reqs <-chan *gossh.Request) {
	SSHServer := sess.Context().Value("extServer").(*SSHServer)
	for req := range reqs {
		SSHServer.addSessionRequest(sess.Context().SessionID(), req.Type)
		switch req.Type {
		case "shell", "exec":
			if sess.handled {
				log.Errorf("request: %s, session already handled", req.Type)
				req.Reply(false, nil)
				continue
			}

			var payload = struct{ Value string }{}
			gossh.Unmarshal(req.Payload, &payload)
			sess.rawCmd = payload.Value

			log.Tracef("request: %s: %s", req.Type, sess.rawCmd)
			sess.handled = true

			go func() {
				sess.handler(sess)
				sess.Exit(0)
			}()
		case "subsystem":
			if sess.handled {
				log.Errorf("request: %s, session already handled", req.Type)
				req.Reply(false, nil)
				continue
			}
			var payload = struct{ Value string }{}
			gossh.Unmarshal(req.Payload, &payload)
			sess.subsystem = payload.Value

			log.Tracef("request: %s: %s", req.Type, sess.subsystem)
			// req.Reply(false, nil)
			sess.handled = true
			req.Reply(true, nil)

			go func() {
				sess.handler(sess)
				sess.Exit(0)
			}()
		case "env":
			if sess.handled {
				log.Errorf("request: %s, session already handled", req.Type)
				req.Reply(false, nil)
				continue
			}
			var kv struct{ Key, Value string }
			gossh.Unmarshal(req.Payload, &kv)
			log.Tracef("request: env %s=%s", kv.Key, kv.Value)
			sess.env = append(sess.env, fmt.Sprintf("%s=%s", kv.Key, kv.Value))
			req.Reply(true, nil)
		case "signal":
			var payload struct{ Signal string }
			gossh.Unmarshal(req.Payload, &payload)
			log.Tracef("request: signal: %s", payload.Signal)
			sess.Lock()
			if sess.sigCh != nil {
				sess.sigCh <- ssh.Signal(payload.Signal)
			} else {
				if len(sess.sigBuf) < maxSigBufSize {
					sess.sigBuf = append(sess.sigBuf, ssh.Signal(payload.Signal))
				}
			}
			sess.Unlock()
		case "pty-req":
			if sess.handled || sess.pty != nil {
				log.Errorf("request: %s, session already handled or pty already set", req.Type)
				req.Reply(false, nil)
				continue
			}
			ptyReq, ok := parsePtyRequest(req.Payload)
			if !ok {
				log.Errorf("request: pty-req !ok")
				req.Reply(false, nil)
				continue
			}
			if sess.ptyCb != nil {
				ok := sess.ptyCb(sess.ctx, ptyReq)
				if !ok {
					log.Errorf("request: pty-req ptyCb !ok")
					req.Reply(false, nil)
					continue
				}
			}
			log.Tracef("request: %s", req.Type)
			sess.pty = &ptyReq
			sess.winch = make(chan ssh.Window, 1)
			sess.winch <- ptyReq.Window
			defer func() { //nolint:staticcheck
				// when reqs is closed
				close(sess.winch)
			}()
			req.Reply(ok, nil)
		case "window-change":
			if sess.pty == nil {
				log.Errorf("request: %s, pty is nil", req.Type)
				req.Reply(false, nil)
				continue
			}
			win, ok := parseWinchRequest(req.Payload)
			if ok {
				sess.pty.Window = win
				sess.winch <- win
			}
			log.Tracef("request: %s", req.Type)
			req.Reply(ok, nil)
		// Agent forwarding request
		// case agentRequestType:
		case "auth-agent-req@openssh.com":
			var payload = struct{ Value string }{}
			gossh.Unmarshal(req.Payload, &payload)
			log.Tracef("request: %s: %s", req.Type, payload.Value)
			SSHServer.setSessionAgent(sess.Context().SessionID(), true)
			req.Reply(true, nil)
		case "break":
			ok := false
			sess.Lock()
			if sess.breakCh != nil {
				log.Errorf("request: %s, break sent", req.Type)
				sess.breakCh <- true
				ok = true
			} else {
				log.Errorf("request: %s, breakCh is nil", req.Type)
			}
			req.Reply(ok, nil)
			sess.Unlock()
		// X11 forwarding request
		case "x11-req":
			var payload = struct{ Value string }{}
			gossh.Unmarshal(req.Payload, &payload)
			log.Tracef("request: %s: %s", req.Type, payload.Value)
			SSHServer.setSessionX11(sess.Context().SessionID(), true)
		default:
			SSHServer.addSessionRequest(sess.Context().SessionID(), "unknown request: "+req.Type)
			log.Errorf("request: unknown request type: %s", req.Type)
			req.Reply(false, nil)
		}
	}
}

// Copied from https://github.com/gliderlabs/ssh/blob/master/util.go
// since they are non-public and session needs them...

func parsePtyRequest(s []byte) (pty ssh.Pty, ok bool) {
	term, s, ok := parseString(s)
	if !ok {
		return
	}
	width32, s, ok := parseUint32(s)
	if !ok {
		return
	}
	height32, _, ok := parseUint32(s)
	if !ok {
		return
	}
	pty = ssh.Pty{
		Term: term,
		Window: ssh.Window{
			Width:  int(width32),
			Height: int(height32),
		},
	}
	return
}

func parseWinchRequest(s []byte) (win ssh.Window, ok bool) {
	width32, s, ok := parseUint32(s)
	if width32 < 1 {
		ok = false
	}
	if !ok {
		return
	}
	height32, _, ok := parseUint32(s)
	if height32 < 1 {
		ok = false
	}
	if !ok {
		return
	}
	win = ssh.Window{
		Width:  int(width32),
		Height: int(height32),
	}
	return
}

func parseString(in []byte) (out string, rest []byte, ok bool) {
	if len(in) < 4 {
		return
	}
	length := binary.BigEndian.Uint32(in)
	if uint32(len(in)) < 4+length {
		return
	}
	out = string(in[4 : 4+length])
	rest = in[4+length:]
	ok = true
	return
}

func parseUint32(in []byte) (uint32, []byte, bool) {
	if len(in) < 4 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(in), in[4:], true
}

// sshanity/server/info.go
// SPDX-License-Identifier: ISC
// Copyright 2015 Filippo Valsorda

// sessionInfo is derived from sessionInfo from
// https://github.com/FiloSottile/whoami.filippo.io

package server

import (
	gossh "golang.org/x/crypto/ssh"
)

type sessionInfo struct {
	User     string
	Keys     []gossh.PublicKey
	Requests []string
	AgentFwd bool
	X11Fwd   bool
	Roaming  bool
}

func (srv *SSHServer) newSessionInfo(sessionID string, user string, key gossh.PublicKey) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	si := srv.sessionInfo[sessionID]
	si.User = user
	si.Keys = append(si.Keys, key)
	srv.sessionInfo[sessionID] = si
}

func (srv *SSHServer) addSessionRequest(sessionID string, request string) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	si := srv.sessionInfo[sessionID]
	si.Requests = append(si.Requests, request)
	srv.sessionInfo[sessionID] = si
}

func (srv *SSHServer) deleteSessionInfo(sessionID string) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	delete(srv.sessionInfo, sessionID)
}

func (srv *SSHServer) getSessionInfo(sessionID string) (sessionInfo, bool) {
	srv.mu.RLock()
	defer srv.mu.RUnlock()

	info, exists := srv.sessionInfo[sessionID]
	return info, exists
}

func (srv *SSHServer) setSessionAgent(sessionID string, agentFwd bool) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	si := srv.sessionInfo[sessionID]
	si.AgentFwd = agentFwd
	srv.sessionInfo[sessionID] = si
}

func (srv *SSHServer) setSessionRoaming(sessionID string, roaming bool) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	si := srv.sessionInfo[sessionID]
	si.Roaming = roaming
	srv.sessionInfo[sessionID] = si
}

func (srv *SSHServer) setSessionX11(sessionID string, x11Fwd bool) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	si := srv.sessionInfo[sessionID]
	si.X11Fwd = x11Fwd
	srv.sessionInfo[sessionID] = si
}

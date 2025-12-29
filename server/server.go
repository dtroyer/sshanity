// sshanity/server/server.go
// SPDX-License-Identifier: BSD-3-Clause

// Package server implements an SSH test server for sanity checking
// SSH client configurations.
package server

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"
)

const (
	DefaultBanner      = "sshanity - SSH Sanity Check\n"
	DefaultBindAddress = "::"
	DefaultPort        = 2222

	DefaultHandshakeTimeout = 60   // seconds
	DefaultIdleTimeout      = 300  // seconds
	DefaultKeepAlive        = 20   // seconds
	DefaultMaxTimeout       = 3600 // seconds
)

var (
	// This is left empty to be filled by the caller or at build-time
	// Host key is in PEM-encoded format with either embedded newlines
	//  or "\n" escapes separating the lines
	FallbackHostKey string = ""
)

// SSHConfig contains the settings that can be set via a config file
type SSHConfig struct {
	HostKey []byte `yaml:"hostkey,omitempty"` // PEM file format
	Address string `yaml:"address,omitempty"` // IPv4 or IPv6
	Port    int    `yaml:"port,omitempty"`
}

// SSHServer wraps ssh.Server and includes callback functions to
// log all callbacks as they occur
type SSHServer struct {
	ctx          ssh.Context
	HostKey      []byte // PEM file format
	Address      string // IPv4 or IPv6
	Port         int
	listenConfig *net.ListenConfig
	SSHServer    *ssh.Server

	mu          sync.RWMutex
	sessionInfo map[string]sessionInfo
}

func SetupServer(config SSHConfig) *SSHServer {
	if config.HostKey == nil {
		log.Warnf("No host key loaded, using fallback: %s", FallbackHostKey)
		config.HostKey = []byte(FallbackHostKey)
	}
	if config.Address == "" {
		config.Address = DefaultBindAddress
	}
	if config.Port == 0 {
		config.Port = DefaultPort
	}

	// Configure SSHServer
	SSHServer := &SSHServer{
		HostKey: config.HostKey,
		Address: config.Address,
		Port:    config.Port,
		listenConfig: &net.ListenConfig{
			KeepAlive: DefaultKeepAlive * time.Second,
		},
		sessionInfo: make(map[string]sessionInfo),
	}

	return SSHServer
}

func (srv *SSHServer) GetAgentRequestHandler() ssh.RequestHandler {
	return func(ctx ssh.Context, srvx *ssh.Server, req *gossh.Request) (bool, []byte) {
		log.Infof("AgentRequestHandler(): %s", req.Type)

		srv.addSessionRequest(ctx.SessionID(), "agent")
		srv.setSessionAgent(ctx.SessionID(), true)

		return false, nil
	}
}

func (srv *SSHServer) GetBannerHandler() ssh.BannerHandler {
	return func(ctx ssh.Context) string {
		log.Infof("BannerHandler(): %s", ctx.SessionID())

		return DefaultBanner
	}
}

func (srv *SSHServer) GetConnCallback() ssh.ConnCallback {
	return func(ctx ssh.Context, conn net.Conn) net.Conn {
		log.Info("ConnCallback()")

		// Save our server object for use inside the session
		ctx.SetValue("extServer", srv)

		return conn
	}
}

func (srv *SSHServer) GetKeyboardInteractiveHandler() ssh.KeyboardInteractiveHandler {
	return func(ctx ssh.Context, challenger gossh.KeyboardInteractiveChallenge) bool {
		log.Infof("KeyboardInteractiveHandler()")

		return true
	}
}

func (srv *SSHServer) GetPasswordHandler() ssh.PasswordHandler {
	return func(ctx ssh.Context, password string) bool {
		log.Infof("PasswordHandler(): %s", password)

		return true
	}
}

func (srv *SSHServer) GetPtyCallback() ssh.PtyCallback {
	return func(ctx ssh.Context, pty ssh.Pty) bool {
		log.Infof("PtyCallback(): %+v", pty)

		return true
	}
}

func (srv *SSHServer) GetPublicKeyHandler() ssh.PublicKeyHandler {
	return func(ctx ssh.Context, publicKey ssh.PublicKey) bool {
		log.Infof("PublicKeyHandler(): %s key for %s@%s", publicKey.Type(), ctx.User(), ctx.RemoteAddr())

		srv.newSessionInfo(ctx.SessionID(), ctx.User(), publicKey)

		return false
	}
}

func (srv *SSHServer) GetServerConfigCallback() ssh.ServerConfigCallback {
	return func(ctx ssh.Context) *gossh.ServerConfig {
		log.Info("ServerConfigCallback()")

		log.Debugf("HostSigners: %+v", srv.SSHServer.HostSigners)

		return &gossh.ServerConfig{}
	}
}

func (srv *SSHServer) GetSessionRequestCallback() ssh.SessionRequestCallback {
	return func(session ssh.Session, requestType string) bool {
		log.Infof("SessionRequestCallback(): %s@%s requestType=%s", session.User(), session.RemoteAddr(), requestType)

		return true
	}
}

func (srv *SSHServer) GetShellHandler() func(ssh.Session) {
	return func(s ssh.Session) {
		sessionID := s.Context().SessionID()
		log.Infof("ShellHandler(): %s@%s", s.User(), s.RemoteAddr())

		defer func() {
			// Dump the results at session close
			s.Write([]byte("Session ID: " + sessionID + "\n"))
			s.Write([]byte("Server version: " + s.Context().ServerVersion() + "\n"))
			s.Write([]byte("Client version: " + s.Context().ClientVersion() + "\n"))
			s.Write([]byte("User: " + s.User() + "\n"))
			s.Write([]byte("Remote Address: " + s.RemoteAddr().String() + "\n"))
			s.Write([]byte("Environment:\n  " + strings.Join(s.Environ(), "\n  ") + "\n"))

			si, _ := srv.getSessionInfo(sessionID)

			s.Write([]byte("Public keys:\n"))
			for _, key := range si.Keys {
				s.Write([]byte("  " + string(gossh.MarshalAuthorizedKey(key))))
			}

			s.Write([]byte("Requests:\n"))
			for _, req := range si.Requests {
				s.Write([]byte("  " + req + "\n"))
			}

			s.Write([]byte("Agent Forwarding: " + strconv.FormatBool(si.AgentFwd) + "\n"))
			s.Write([]byte("X11 Forwarding: " + strconv.FormatBool(si.X11Fwd) + "\n"))
			s.Write([]byte("Roaming: " + strconv.FormatBool(si.Roaming) + "\n"))

			srv.deleteSessionInfo(sessionID)
		}()

		log.Infof("session closed: %s", sessionID)
	}
}

// RunServer configured callback functions and starts the ssh listener
func (srv *SSHServer) RunServer() error {
	srv.SSHServer = &ssh.Server{
		Handler:     srv.GetShellHandler(),
		IdleTimeout: DefaultIdleTimeout * time.Second,
		MaxTimeout:  DefaultMaxTimeout * time.Second,
		// Add when released in gliderlabs/ssh
		// HandshakeTimeout: DefaultHandshakeTimeout * time.Second,
		RequestHandlers: map[string]ssh.RequestHandler{
			"hostkeys@openssh.com": func(ctx ssh.Context, srvx *ssh.Server, req *gossh.Request) (bool, []byte) {
				log.Infof("GetHostKeysRequestHandler(): %s", req.Type)
				srv.addSessionRequest(ctx.SessionID(), "hostkeys")
				return false, nil
			},
			"roaming@appgate.com": func(ctx ssh.Context, srvx *ssh.Server, req *gossh.Request) (bool, []byte) {
				log.Infof("GetRoamingRequestHandler(): %s", req.Type)
				srv.addSessionRequest(ctx.SessionID(), "roaming")
				srv.setSessionRoaming(ctx.SessionID(), true)
				return false, nil
			},
		},
		ChannelHandlers: map[string]ssh.ChannelHandler{
			"agent-connection": func(srv *ssh.Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx ssh.Context) {
				log.Infof("agent-connection ChannelHandler")
				channel, requests, err := newChan.Accept()
				if err != nil {
					log.Errorf("ssh: could not accept agent-connection channel: %v", err)
					return
				}
				defer channel.Close()

				for req := range requests {
					log.Tracef("ssh: agent-connection handleRequests: received request: %v", req.Type)
					req.Reply(false, nil)
				}
			},
			"session": DefaultSessionHandler,
			"x11-connection": func(srv *ssh.Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx ssh.Context) {
				log.Infof("x11-connection ChannelHandler")
				channel, requests, err := newChan.Accept()
				if err != nil {
					log.Errorf("ssh: could not accept x11-connection channel: %v", err)
					return
				}
				defer channel.Close()

				for req := range requests {
					log.Tracef("ssh: x11-connection handleRequests: received request: %v", req.Type)
					req.Reply(false, nil)
				}
			},
		},
	}

	// Set up host key, convert "\n" to '\n' (2 chars to a newline char)
	srv.SSHServer.SetOption(ssh.HostKeyPEM(bytes.Replace(srv.HostKey, []byte{'\\', 'n'}, []byte{'\n'}, -1)))

	// Set up auth callbacks
	srv.SSHServer.BannerHandler = srv.GetBannerHandler()
	srv.SSHServer.SetOption(ssh.KeyboardInteractiveAuth(srv.GetKeyboardInteractiveHandler()))
	srv.SSHServer.SetOption(ssh.PasswordAuth(srv.GetPasswordHandler()))
	srv.SSHServer.SetOption(ssh.PublicKeyAuth(srv.GetPublicKeyHandler()))
	srv.SSHServer.PtyCallback = srv.GetPtyCallback()
	srv.SSHServer.ConnCallback = srv.GetConnCallback()
	srv.SSHServer.ServerConfigCallback = srv.GetServerConfigCallback()
	srv.SSHServer.SessionRequestCallback = srv.GetSessionRequestCallback()

	log.Infof("starting server on %s:%d", srv.Address, srv.Port)
	listener, err := srv.listenConfig.Listen(srv.ctx, "tcp", fmt.Sprintf("[%s]:%d", srv.Address, srv.Port))
	if err != nil {
		log.Errorf("server listen failure on %s: %v", fmt.Sprintf("[%s]:%d", srv.Address, srv.Port), err)
		return err
	}
	return srv.SSHServer.Serve(listener)
}

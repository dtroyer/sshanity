# sshanity

**sshanity**
[**shan**-i-tee] / ˈʃæŋ ɪ ti /

NOUN
1. the state of a well-configured secure shell client

`sshanity` is an experimental ssh server that reports various
aspects of the ssh client connecting to it then disconnects the session:

* client and server versions
* username
* remote address:port
* environment
* public keys presented
* ssh protocol requests
* agent forwarding
* X11 forwarding
* roaming

## Try It Out

Running the `sshanity` server is as simple as:

```bash
make build
bin/sshanity
```

This will create a set of host keys in `test-keys` and embed the
ed25519 private key in `ssh_host_ed25519_key` into the `sshanity`
binary.  (Yes, this needs to be externally configurable, it's on
the ToDo list)

The server will start on port 2222 and wait for a connection.

## Connecting to sshanity

You can use any ssh protocol 2 client to connect, in fact this can
be useful when comparing client implementations with each other
to see what they are negotiating with the server.

These examples assume a recent OpenSSH client and will note version-specific
configurations as they appear.

### Basic Connection

```bash
ssh -p 2222 localhost
```

### Agent Forwarding

```bash
ssh -A -p 2222 localhost
```

### X11 Forwarding

This will only wotk if your client system has xauth available:

```bash
ssh -X -p 2222 localhost
```

## Public Keys

When public key authentication is enabled the ssh client will present the
server with one or more public keys that it knows about, stopping when
either one is accepted or it runs out.  `sshanity` refuses all public keys
in order to gather all keys that the client is willing to send.

When a single identity file is configured with the `IdentityFile` option
the ssh client will only send that public key, by setting `IdentitiesOnly no` the remaining keys will be sent anyway.

```bash
ssh -o "IdentitiesOnly no" -p 2222 localhost
```

## ToDo

* configuration options/file
  * host key(s)
  * bin address:port
  * logging level
* display port forwarding

## Acknowledgements

`sshanity` was inspired by Filippo Valsorda's
[whoami.filippo.io](https://github.com/FiloSottile/whoami.filippo.io)
project that also looks up the public keys from Github for further
identification.  One major difference is that this uses the
[gliderlabs/ssh](https://github.com/gliderlabs/ssh) as the basis of
the server.

## License

The original code and derivations contained in `shannity` are 
licensed under BSD-3-Clause.

`sshanity` contains code borrowed from two other sources:
* [whoami.filippo.io](https://github.com/FiloSottile/whoami.filippo.io) (ISC license)
* [gliderlabs/ssh](https://github.com/gliderlabs/ssh) (BSD-3-Clause license)

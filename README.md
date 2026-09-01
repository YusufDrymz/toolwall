# toolwall

[Türkçe](README.tr.md) · **English**

Your agent can read your private data. Your agent can read the open internet.
`toolwall` is what stops it from doing both and then sending the result somewhere.

`toolwall` is an information-flow firewall for MCP tool calls: a single Go binary that
sits between an MCP client and an MCP server on stdio, tracks what each session has
already read, and refuses the call that would send it out. The decision is offline and
deterministic -- labels in a committed policy file, no model, no classifier, no service
call -- so the same sequence of calls always produces the same verdict, and every refusal
names the earlier call that caused it.

[![Go Reference](https://pkg.go.dev/badge/github.com/YusufDrymz/toolwall.svg)](https://pkg.go.dev/github.com/YusufDrymz/toolwall)
[![CI](https://github.com/YusufDrymz/toolwall/actions/workflows/ci.yml/badge.svg)](https://github.com/YusufDrymz/toolwall/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Three calls go through the gateway. Send a status mail: fine. Read the private notes:
fine. Send a mail again, now that the notes are in the session:

```
$ toolwall run --server demo --audit audit.jsonl
toolwall: fronting "demo" in enforce mode
toolwall: denied send_email (exfiltration)

$ toolwall audit --file audit.jsonl
16:58:26 call       send_email(body, to)
16:58:26 call       read_notes()
16:58:26 DENIED     send_email
           rule exfiltration: sensitive data was read earlier in this scope
           because call 2 (read_notes) brought sensitive data in
16:58:26 result     send_email
16:58:26 result     read_notes

call         2
result       2
denied       1
```

The client gets a real JSON-RPC error back, written for the model that will read it:

```
toolwall denied this call to "send_email": sensitive data was read earlier in this
scope. Call 2 (read_notes) brought sensitive data into this session. This is a policy
decision, not a transient failure: do not retry, and tell the user which rule blocked it.
```

Each of those three calls is fine on its own. The sequence is the attack, and the
sequence is the thing nothing else in the MCP stack is watching.

## Why this and not the other MCP security tools

The gateway category is busy, and most of it solves a different problem:

| Tool | What it does | What it does not do |
| --- | --- | --- |
| ToolHive, Docker MCP Gateway | isolate the server process: containers, mounts, network, signed images | nothing about what data moves between calls |
| Pomerium, Kuadrant | identity: who may reach which server and tool, OAuth, rate limits | an authorised user's own agent exfiltrating their own data |
| Agent Scan (formerly MCP-Scan) | scan definitions for poisoning and shadowing, before or around a session | enforce a rule about the order of calls at runtime |

`toolwall` is the missing one: **cross-call data flow**. It composes with the others
rather than replacing them -- run your servers in ToolHive, put identity in front with
Pomerium, and let `toolwall` decide whether this particular call may go out given what
this particular session already read.

## Install

```sh
go install github.com/YusufDrymz/toolwall/cmd/toolwall@latest
```

Requires Go 1.24+. Builds with `CGO_ENABLED=0`; the only non-test dependency is
`gopkg.in/yaml.v3`.

Prebuilt binaries are on the [releases](https://github.com/YusufDrymz/toolwall/releases)
page.

## Quickstart

**1. Take an inventory.** Point `init` at a server and it lists what the server exposes,
guesses labels and pins every definition:

```sh
toolwall init --server demo -- go run ./examples/demo-server
```

```yaml
version: 1
mode: observe
servers:
    demo:
        command: go
        args:
            - run
            - ./examples/demo-server
tools:
    demo.read_notes:
        labels: [sensitive]
        digest: sha256:4b42ab67d786...
        note: 'suggested: looks like it reads private data (private)'
    demo.fetch_url:
        labels: [untrusted]
        digest: sha256:dbb68256376d...
    demo.send_email:
        labels: [sink]
        digest: sha256:26ac1cab73fd...
```

**2. Fix the labels.** The guesses are a starting point and they are wrong often enough
that the file says so. Three labels, and the question for each tool is short:

- `sensitive` -- does calling it bring private data into the session?
- `untrusted` -- does it bring in content someone outside your trust boundary wrote?
- `sink` -- can calling it send data out?

A tool can carry more than one. A URL fetcher is usually both `untrusted` and `sink`:
the page is attacker-controlled, and the URL itself is an exit -- everything you know
fits in a query string.

**3. Put the wall in front.** In your MCP client config, launch `toolwall` instead of
the server:

```json
{
  "mcpServers": {
    "demo": {
      "command": "toolwall",
      "args": ["run", "--config", "/path/to/toolwall.yaml", "--server", "demo"]
    }
  }
}
```

Start in `mode: observe` -- every violation is reported, nothing is blocked -- and read
the log for a day before switching to `enforce`.

**4. Keep it honest in CI.** `verify` reconnects to every server and fails when a
definition you already reviewed has changed underneath you:

```sh
$ toolwall verify
[DRIFT] demo.read_notes definition changed since it was reviewed
        pinned sha256:4b42ab67d786...
        actual sha256:9f1c0a3e5521...

1 violation(s)
```

That is the rug pull: a server that ships a harmless tool, waits for approval, then
edits the description to carry instructions. `verify` exits 1 in CI. At runtime the
gateway drops the mutated tool from `tools/list`, so the poisoned text never reaches
the model, and refuses calls to it.

The refusal does not depend on the client listing tools first. A client that cached
the list from an earlier session never sends `tools/list`, and two requests sent
together do not arrive in a helpful order, so a call to a pinned tool that has not
been checked yet makes the gateway ask the server for its definitions and wait for
the answer. If that check cannot be completed, the call is refused rather than
allowed: a pin that is only enforced when the timing suits it is not a pin.

## Try a policy before you trust it

`explain` runs a policy against a sequence of calls without connecting to anything, so you
can see what a rule does before it starts blocking real work:

```sh
$ toolwall explain hr.read_record 'mail.send={"to":"attacker@evil.test"}'
policy toolwall.yaml, mode enforce -- offline simulation, pins not checked

 1. allow      hr.read_record  +sensitive
 2. DENIED     mail.send
        rule exfiltration: sensitive data was read earlier in this scope
        because call 1 (read_record) brought sensitive data in
```

Each argument is a `server.tool`, optionally with inline JSON arguments after `=` to
exercise argument rules. It exits non-zero if any call is denied, so it drops straight
into a test. Being offline it cannot check pins against a live server; everything else --
labels, flow rules, argument rules, the shared scope -- is exactly what the gateway does.

## Multiple servers, one scope

`run` fronts a single server. `serve` fronts every server in the policy at once,
behind one shared flow scope -- and the shared scope is the point:

```sh
toolwall serve
```

Tools are namespaced with the server id the policy already uses (`hr.read_record`,
`mail.send`). Put toolwall in your client config once and it aggregates all of them:

```json
{
  "mcpServers": {
    "toolwall": {
      "command": "toolwall",
      "args": ["serve", "--config", "/path/to/toolwall.yaml"]
    }
  }
}
```

### Remote servers over HTTP

A server can be a local command or a remote Streamable HTTP endpoint; `serve` fronts a
mix of the two behind the same scope. Point `init` at a URL instead of a command:

```sh
toolwall init --server hr --url https://hr.internal/mcp --header "Authorization: Bearer ${HR_TOKEN}"
```

```yaml
servers:
    hr:
        url: https://hr.internal/mcp
        headers:
            Authorization: Bearer ${HR_TOKEN}
    mail:
        command: mail-mcp
```

Header values expand `${ENV}` at connect time, so a committed policy never holds a
credential. toolwall speaks the 2026-07-28 transport -- the required `MCP-Protocol-Version`,
`Mcp-Method` and `Mcp-Name` headers, SSE responses, and the `Mcp-Param-*` mirroring a
server can demand -- and falls back to the older session-based Streamable HTTP shape when
an upstream still speaks it. Plain `http://` to anything but loopback is refused unless you
opt in with `insecure: true`, because a bearer token does not belong on the wire in clear.
Reading a record from the remote `hr` server and sending it out through the local `mail`
server is still one scope, still refused.

Now the flow rules reach across servers. Reading a record on the `hr` server and
sending it out through the `mail` server is one session touching `sensitive` and then
`sink`, so it is refused -- exactly the crossing that per-server isolation and identity
gateways cannot see, because it happens between two servers they each guard in isolation.

Populate the policy one server at a time with `init --server`, and `verify` checks all
of them.

## The rules

The default policy is two rules, and they are the reason the tool exists:

```yaml
flow:
  deny:
    - name: exfiltration
      sink: [sink]
      after: [sensitive]
    - name: injection-exfiltration
      sink: [sink]
      after: [untrusted]
```

Read it as: refuse a call to anything labelled `sink` once this session has already
touched something labelled `sensitive` (or `untrusted`). Labels in `after` are ANDed, so
you can write the narrower version instead:

```yaml
flow:
  deny:
    - name: trifecta
      sink: [sink]
      after: [sensitive, untrusted]
      reason: private data, attacker-controlled content, and an exit in one session
```

Labels are free-form. Any label a rule mentions can be used, and a label no rule mentions
is a load-time error -- a typo that quietly turns a tool into a non-sink is exactly the
failure this tool exists to prevent.

Arguments can be constrained too, which is often enough on its own:

```yaml
tools:
    demo.send_email:
        labels: [sink]
        args:
            to:
                allow: ['@yourcompany\.com$']
            body:
                max_len: 4096
```

## What it does not do

Being clear about this matters more than the feature list.

- **It is not a sandbox.** A tool that runs code can do whatever the process can do;
  `toolwall` sees JSON-RPC, not syscalls. Use ToolHive or the Docker gateway for
  isolation and put `toolwall` inside it.
- **It cannot label your tools for you.** The heuristics in `init` are a drafting aid.
  A gateway with wrong labels is worse than none, because it feels like protection.
- **One call can still be an exfiltration.** If a tool both reads private data and
  reaches the network, no ordering rule helps. Label those `sink` from the start and
  constrain their arguments.
- **The scope is the gateway process.** Under `run` and `serve` alike, one toolwall
  process is one flow scope; `serve` shares it across every server it fronts, which is
  the feature. The 2026-07-28 revision is explicit that a connection is not a session
  and gives a proxy no conversation identifier, so if your client sets a correlation id
  in `_meta`, point `--scope-key` at it to track flows per conversation instead.
- **`serve` proxies tools and prompts.** Resources are not aggregated yet; a client
  that needs them should reach that server directly.
- **`run` is stdio only.** It is a byte proxy over a spawned child. Remote Streamable
  HTTP servers go through `serve`, which talks to them as a real MCP client.
- **The model can still talk.** `toolwall` guards tool calls. It does not read the
  model's replies to the user.

## Protocol support

Both transports and both eras, without configuration. Local servers run on stdio; remote servers run over Streamable HTTP. The 2026-07-28 revision dropped the `initialize`
handshake and made every request self-contained; everything up to 2025-11-25 needs a
session. `init` and `verify` probe with `server/discover` and fall back to `initialize`
exactly as the spec's stdio compatibility rules describe. The gateway itself rewrites
neither: whatever the client sends is what the server sees, so a modern client and a
legacy server keep whatever they had.

## Development

```sh
go test -race -cover ./...
```

The tests run a scriptable fake server (`internal/fakemcp`) as a child process, so the
awkward cases -- a legacy server, a server that rejects requests without `_meta`, a
server that mutates a tool description between listings, a client that pipelines two
calls to race the wall -- are all covered without touching the network.

## License

MIT

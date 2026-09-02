# toolwall and SAFE-MCP

[SAFE-MCP](https://github.com/SAFE-MCP/safe-mcp) is an OpenSSF framework that catalogs
MCP attack techniques in the style of MITRE ATT&CK, each with a `SAF-T####` identifier.
This page maps toolwall's controls onto the techniques they touch, and is honest about
the ones they do not.

One framing first, because it decides everything below. **toolwall does not detect
prompt injection or tell a good tool call from a bad one.** It assumes the agent may
already be compromised and governs what a compromised agent can *do*: which tools it may
reach, what may leave the machine, and whether a tool is still the one you reviewed. It
is a blast-radius control, not a content classifier. So it maps well onto the
*persistence*, *exfiltration* and *lateral-movement* techniques, and barely at all onto
the *execution* techniques that live inside a server.

Coverage is graded plainly:

- **Mitigates** — a correctly written policy stops the technique at toolwall.
- **Partial** — toolwall raises the cost or narrows the technique but does not close it.
- **Detects** — toolwall does not prevent it, but the audit trail records it.

## Definition integrity — pins and `verify`

toolwall fingerprints every reviewed tool definition (name, description, both schemas,
annotations) and, at runtime, drops from `tools/list` any tool whose definition changed,
refusing calls to it; `toolwall verify` fails CI on the same drift.

| Technique | Name | Control | Coverage |
| --- | --- | --- | --- |
| [SAF-T1201](https://github.com/SAFE-MCP/safe-mcp/tree/main/techniques/SAF-T1201) | MCP Rug Pull Attack | pinned digest; mutated definition dropped at runtime, `verify` fails CI | Mitigates |
| [SAF-T1205](https://github.com/SAFE-MCP/safe-mcp/tree/main/techniques/SAF-T1205) | Persistent Tool Redefinition | digest is compared every session, so a change that survives a restart still fails the pin | Mitigates |
| [SAF-T1001](https://github.com/SAFE-MCP/safe-mcp/tree/main/techniques/SAF-T1001) | Tool Poisoning Attack | a poisoned description on a pinned tool never reaches the model; a *new* tool is caught at the next review, not on first sight | Partial |
| [SAF-T1008](https://github.com/SAFE-MCP/safe-mcp/tree/main/techniques/SAF-T1008) | Tool Shadowing Attack | `serve` namespaces every tool with its server id, so two servers' same-named tools cannot silently shadow each other | Partial |
| [SAF-T1301](https://github.com/SAFE-MCP/safe-mcp/tree/main/techniques/SAF-T1301) | Cross-Server Tool Shadowing | same namespacing; a shadowing server gets a distinct `server.tool` name rather than overriding another | Partial |

## Data flow — labels, rules and the shared scope

toolwall labels tools `sensitive` / `untrusted` / `sink` and refuses a sink once the
scope has taken in either. Under `serve` the scope is shared across servers, so the
"read here, send there" move is caught even when the two servers are different.

| Technique | Name | Control | Coverage |
| --- | --- | --- | --- |
| [SAF-T1910](https://github.com/SAFE-MCP/safe-mcp/tree/main/techniques/SAF-T1910) | Covert Channel Exfiltration | a `sink` call is denied once the scope holds `sensitive` or `untrusted` data | Mitigates |
| [SAF-T1911](https://github.com/SAFE-MCP/safe-mcp/tree/main/techniques/SAF-T1911) | Parameter Exfiltration | flow rule denies the sink; argument `allow`/`deny`/`max_len` constrain what a permitted sink may carry | Mitigates |
| [SAF-T1901](https://github.com/SAFE-MCP/safe-mcp/tree/main/techniques/SAF-T1901) | Outbound Webhook C2 | an `http.post`-style sink is denied after the scope is stained; an argument allowlist pins the destination host | Mitigates |
| [SAF-T1701](https://github.com/SAFE-MCP/safe-mcp/tree/main/techniques/SAF-T1701) | Cross-Tool Contamination | the shared cross-server scope refuses data read on one server leaving through another | Mitigates |
| [SAF-T1703](https://github.com/SAFE-MCP/safe-mcp/tree/main/techniques/SAF-T1703) | Tool-Chaining Pivot | for the data dimension: a chain that ends at a sink is judged on everything the chain touched, not the last hop alone | Partial |

The *collection* techniques — [SAF-T1801](https://github.com/SAFE-MCP/safe-mcp/tree/main/techniques/SAF-T1801)
Automated Data Harvesting, [SAF-T1803](https://github.com/SAFE-MCP/safe-mcp/tree/main/techniques/SAF-T1803)
Database Dump, [SAF-T1804](https://github.com/SAFE-MCP/safe-mcp/tree/main/techniques/SAF-T1804)
API Data Harvest — are the *read* side. toolwall does not stop an agent from reading; it
stops the send that would follow, and the audit trail records the reads. Treat these as
**Detects**, with the exfiltration they feed graded above.

## Arguments and routing

| Technique | Name | Control | Coverage |
| --- | --- | --- | --- |
| [SAF-T1105](https://github.com/SAFE-MCP/safe-mcp/tree/main/techniques/SAF-T1105) | Path Traversal via File Tool | a `deny` pattern such as `\.\.` on a path argument, plus an `allow` prefix, rejects the traversal | Mitigates |
| [SAF-T1101](https://github.com/SAFE-MCP/safe-mcp/tree/main/techniques/SAF-T1101) | Command Injection | argument `allow`/`deny`/`max_len` narrow what reaches the server; this is not a sandbox and does not stop RCE from an allowed value | Partial |
| [SAF-T1103](https://github.com/SAFE-MCP/safe-mcp/tree/main/techniques/SAF-T1103) | Fake Tool Invocation | `unknown_tools: deny` refuses any tool not described in the policy; the gateway rejects a name that routes to no server | Partial |

## Everything — the audit trail

Every call, result, denial and pin mismatch is written to an append-only JSONL trail
with the evidence behind each decision (`toolwall audit` reads it back as a timeline).
This is the **Detects** layer under all of the above, and the record you reach for after
an incident to answer "what did the agent touch, and in what order".

## Out of scope

Named plainly so the boundary is not mistaken for coverage:

- **Prompt injection itself** ([SAF-T1102](https://github.com/SAFE-MCP/safe-mcp/tree/main/techniques/SAF-T1102)). toolwall does not inspect content for injected instructions. It limits what an injected agent can do — see the data-flow section — rather than trying to spot the injection.
- **Code execution inside a server** (the full extent of [SAF-T1101](https://github.com/SAFE-MCP/safe-mcp/tree/main/techniques/SAF-T1101)). toolwall sees JSON-RPC, not syscalls. Run servers in a sandbox such as [ToolHive](https://github.com/stacklok/toolhive) or the Docker MCP gateway and put toolwall inside it.
- **Identity and token attacks** ([SAF-T1706](https://github.com/SAFE-MCP/safe-mcp/tree/main/techniques/SAF-T1706) OAuth Token Pivot Replay, [SAF-T1707](https://github.com/SAFE-MCP/safe-mcp/tree/main/techniques/SAF-T1707) CSRF Token Relay). Authentication and authorization belong to an identity-aware proxy such as Pomerium or Kuadrant.
- **Shared-memory and multi-agent bus attacks** ([SAF-T1702](https://github.com/SAFE-MCP/safe-mcp/tree/main/techniques/SAF-T1702), [SAF-T1705](https://github.com/SAFE-MCP/safe-mcp/tree/main/techniques/SAF-T1705)). toolwall sits on the MCP tool-call path, not on a vector store or an agent message bus.

Technique names and identifiers here are taken from the SAFE-MCP repository; see it for
the authoritative, evolving catalog.

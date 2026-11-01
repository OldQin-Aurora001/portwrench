English · [中文](NOTICE.md)

# NOTICE — Sources, Attribution, and License

```
 - @dsh-plugins/dsh-env-inspector (MIT)
   https://github.com/webkubor/dsh-env-inspector

 - portkiller (MIT)
   https://github.com/productdevbook/port-killer

We thank the open-source projects dsh-env-inspector and port-killer for inspiring PortWrench.
Without their work, this tool would not be what it is today.
We extend our respect to both projects and their developers.
```

---

## Part One: Referenced Projects (Full Details)

### ① dsh-env-inspector — Its three-stage safety design left a strong impression on us.

The order of these three steps is itself a safety design. We adapted that structure for Windows and added process creation time as an additional identity check.

| Item | Value |
|---|---|
| Plugin name (npm package) | `@dsh-plugins/dsh-env-inspector` |
| GitHub repository | **<https://github.com/webkubor/dsh-env-inspector>** |
| Author / copyright notice | `webkubor` |
| Reference version | `0.2.11` |
| License | **MIT** |
| What we referenced | See the item-by-item comparison below |

**Item-by-item comparison** (the `killProcessOnPort` function in its `lib/index.js` → this project's implementation):

| # | Upstream implementation | PortWrench implementation |
|---|---|---|
| 1 | **Self-protection**: `if (id === process.pid)` prevents the process from killing itself | Protection list + the console's own PID (`console_pid`) |
| 2 | **Self-protection**: `DSH_CORE_PORT_SET.has(p)` protects core ports | `protection.json` port list + the console's own port |
| 3 | **State-consistency check**: verifies that the PID is actually listening on the specified port | **Fresh scan before closing** + `(port, PID, process name)` triple check |
| 4 | **Two-phase termination**: `SIGTERM` → wait 150 ms → send `SIGKILL` if the process is still running | `PostMessageW(WM_CLOSE)` → wait up to 2 seconds (rechecking every 200 ms) → force-kill only if it is still running |
| 5 | **Same-origin check**: reads `Sec-Fetch-Site` to determine the request's origin | The UI channel checks both `Origin` and `Sec-Fetch-Site` |
| 6 | **Collapsing high-numbered ports in the display** | This project groups entries by ownership instead of collapsing them |

**★ Where PortWrench adds safeguards:**

- **Process creation time**: The upstream project checks the `(port, PID)` pair, which is sufficient in many cases. Because PID reuse is more frequent on Windows, PortWrench also checks process creation time, in addition to the `(port, PID, process name)` triple.
- **Three pre-kill checks**: Immediately before running `taskkill`, the tool checks again that the process handle is still valid, the process can be opened, and its creation time still matches. If any check fails, the operation is refused.
- **Two distinct failure outcomes**: It distinguishes between "the target exited on its own" (returns `already_free`) and "the target identity changed" (returns `target_changed`). These require completely different handling.
- **Subtree protection**: If the process tree of a force-kill target contains a protected process, **the entire operation is refused**.
- **Session 0 protection**: Processes in the session used by Windows system services cannot be closed from the panel.
- **Fail-closed handling for unreadable executable paths**: A target whose executable path cannot be read is treated as protected. **Better to leave one process running than to take a chance.**
- **Protection-port self-check**: At startup, the tool checks whether each port in the protection list is actually listening. Ports that are not listening are marked as "historical ports."

> ★ **Mandatory statement**: This project **did not copy any lines of code from `dsh-env-inspector`**.  
> `dsh-env-inspector` is written in JavaScript, while this project is written in Python, so its implementation could not be directly reused.  
> We referenced its **design structure**—protect first, verify identity, then act in stages—and rewrote the implementation from scratch.

### ② port-killer — A clean, well-designed interface that helped cure our fear of bad UI.

Lists, search, refresh, and status indicators may seem ordinary, but they reflect the experience of countless users. We followed that familiar pattern to build our own interface.

| Item | Value |
|---|---|
| Project name (npm package) | `portkiller` |
| GitHub repository | **<https://github.com/productdevbook/port-killer>** |
| Copyright notice | `PortKiller Contributors` |
| Reference version | `3.4.0` |
| License | **MIT** |
| What we referenced | The **information organization** of the port list: list + search + refresh + status indicators |

> ★ **Mandatory statement**: This project **did not copy any lines of code from `port-killer`**.  
> `port-killer` is written in C# / .NET (WPF), while this project is written in Python, so its implementation could not be directly reused.  
> The interface was implemented independently; its classification dimensions, interaction flow, and safety design are all different.

---

## Part Two: Original Implementation

- **Port scanning and display**: PowerShell `Get-NetTCPConnection` scan and a front-end table, including merged entries for multiple bindings
- **Automatic process-recognition rules**: The externalized `rules.json` table matches command lines and process names in `order` priority, preventing broad rules from taking matches from more specific rules
- **Process-tree termination**: `taskkill /T /F`, which terminates child processes along with the parent
- **Four-level status classification**: 🔴 system / 🟡 other / 🟢 self / ⚪ unknown; buttons are disabled or require a second confirmation depending on the level
- **AI Agent loopback API**: `/api/v1/*` with three permission tiers (L0 read-only / L1 UI channel / L2 AI channel)
- **`portctl.py` command-line client**: `list / find / kill / protection / health`
- **`kill-by-port` mode**: Accepts only a port number and fingerprint; the server determines the process identity using a fresh scan in the same request
- **Port knowledge base**: `ports.json` / `ports.md`; knowledge-only data that answers "What is this port usually used for?" and does not affect close decisions
- **Audit log**: `kill_audit.jsonl` records who made the request, when it happened, what was targeted, and the result; it rotates automatically after exceeding 1 MiB
- **Three-layer display-cache defense**: The `fresh` / `cached` entry points are physically isolated, cached results are tagged `_cached`, and the close path asserts that the tag is false
- **`SKILL.md`**: Operating instructions for AI shells
- **Test suite**: Unit tests + end-to-end acceptance tests, including zero-impact assertions such as "deleting the port reference table must not change the close decision"

### Safety Design Principles

These are the boundaries established during design. They are documented so future contributors understand why certain features are intentionally omitted:

- **No one-click kill-all** — bulk operations are a common source of accidental process termination
- **No bulk cleanup by process name** — name matching is inherently ambiguous, and ambiguity creates risk
- **No operations on processes without a listening port** — that would go beyond the scope of port management
- **No acting just because something "looks like" the target** — identity must be supported by verifiable evidence (the triple + creation time)
- **No always-on administrator privileges** — normal user permissions are the supported baseline; we do not elevate for convenience
- **The protection list must self-check** — protecting a port that no process is listening on is like guarding an empty house

---

## Part Three: License

This project is licensed under **MIT** (see [LICENSE](LICENSE)).

**Copyright holder**: 「老秦 Family」（OldQin Family）

**About upstream copyright notices**: MIT requires that upstream copyright notices be retained, but **that requirement applies only when code from the upstream project has been copied**.  
This project copied no code from either project above; therefore, `LICENSE` contains no upstream copyright notices.  
The full attribution and license information for both projects is listed in Part One of this file.

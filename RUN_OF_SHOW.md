# 30-minute live run-of-show

**Audience promise:** a synthetic distributed environment with real, inspectable defensive decisions. Do not describe this as a production SOC, hypervisor firewall, actual VM escape detection or deployed MFA.

## Before the audience arrives

- Start the Render master and Colab agents shortly before the session. Confirm cloud acceptance checklist in `SETUP.md`.
- Keep a tested local copy ready as a fallback. The local launcher prints an operator password; do not screen-share secrets.
- Run all three scenarios once. Export the JSON as clearly labelled **rehearsal evidence**. Reset for the audience. No manufactured success logs.
- Browser zoom around 100–125%; show dashboard on a large screen. Hide terminal credentials and notebook key-entry cells.
- Have the “Defense controls” view and source code ready. Expect roughly seconds per automated scenario; the rest of the session explains evidence. This is a speaking schedule, not a measured 30-minute recording.

## 00:00–03:00 · Scope and architecture

**Click:** Overview.

**Say:** “These are five temporary Python agents. In this cloud rehearsal each runs in Colab, which stands in for a VM. Cloudflare gives the master an HTTPS route to each agent. Our attack patterns are fixed and synthetic. The controls and denied responses are real. None of this targets production data.”

Point to **LOCAL LAB** or **CLOUD LAB** honestly. Local mode is five independent processes, not five cloud machines.

## 03:00–06:00 · Health and trust boundary

**Click:** Infrastructure. Show the five cards and heartbeat ages.

**Say:** “Online means the master recently heard from the agent. It is not proof of an intact inbound tunnel. Each agent has its own key. Management requests are signed and replay checked.”

Explain 8-second heartbeat and 25-second offline threshold. Return to Overview. Choose node-1.

## 06:00–12:00 · Cloud data breach

**Click:** Play on **Cloud data breach**. Watch the live feed. Filter **Detected**, then **Prevented**.

**Say:** “The baseline reader requests five dummy rows. Our scripted actor requests 30 rows repeatedly. Two requests pass. The third would bring the ten-second total to 90, above the limit of 80. That request returns 403 and releases no rows. The actor stays blocked until reset.”

Point to critical severity, source/reporting node, control name and timestamps. The normal requests are not security incidents and do not flood the feed.

**Be precise:** 60 synthetic rows were released before detection. Do not claim zero leakage before the anomaly threshold or a machine-learning model.

Optional code view: `Detector.data()` and the scenario assertions.

## 12:00–18:00 · Identity attack

**Click:** All events; select node-2; play **Identity attack**.

**Say:** “This is one fixed synthetic account, not a real credential list. Three failures inside ten seconds lead to a sixty-second lock on the next attempt. No session is issued while locked. The step-up flag tells a caller fresh verification is required; a complete MFA flow is outside this lab.”

Then show the separate replay incident:

**Say:** “We mint a sandbox token, use it once successfully, then present it again. The registry remembers it is spent and rejects the second redemption with 403. Token contents are never sent to the dashboard.”

Expected cumulative totals: **3 detections / 3 preventions** after breach + identity. Explain why identity gives two incidents.

## 18:00–23:00 · Cross-node boundary

**Click:** Select node-1 (with another node online); play **Virtualization threat**.

**Say:** “The orchestrator arms a single-use probe on another self-owned agent. The source sends exactly one fixed request. It can reach the destination over the tunnel, but it is not the master. The destination refuses that peer identity with HTTP 401, invokes no internal service and reports its own signed prevention evidence.”

Point to the destination reporting node on the prevented event, and source-node detail. Open the exported JSON if needed to show `source_node` vs `node_id`.

**Say:** “This is application-level segmentation and authentication. It is not proof of a hypervisor escape defense, OS firewall, or Cloudflare firewall rule. The separate logical internal-service route also denies before opening a connection.”

A timeout is an **inconclusive/failed run**, not “attack prevented.” No destination evidence means no successful run.

## 23:00–26:00 · Review and export

**Click:** Event explorer → Prevented; filter Critical then All severities. Export.

Expected clean totals: **4 detections, 4 preventions, 1 critical incident, 12 stage events**. Timestamp order may differ from receipt order across hosts; the feed sorts origin timestamps. Explain correlation via incident/run IDs.

**Click:** Defense controls. Review the policy limits and the honest scope notes.

## 26:00–28:00 · Repeatability and recovery

**Click:** Reset demo (confirm), then Run full simulation if time allows. Show returning counters and independently enforced decisions. This is a fresh run; detector state resets at each scenario start.

Optional: stop an unused node, wait 25 seconds, show offline status; restart and observe re-registration. Do not spend this buffer chasing a tunnel.

## 28:00–30:00 · Wrap up and questions

**Say:** “The pattern is observe, analyze and enforce. We demonstrated volume limits, identity rate limits and token replay rejection, plus a destination authentication boundary. Production would replace these Colab stand-ins with real instances, persistent telemetry, proper distributed state and network enforcement, full MFA, and operational monitoring.”

Stop agents and disconnect Colab runtimes after the presentation. Export evidence before stopping Render if it needs to be retained.

## Failure fallback script

| Failure | What to do | What to say |
|---|---|---|
| One tunnel drops | Choose another online source; for peer use two reachable nodes | “Recent heartbeat and reverse reachability are different. The run is failed, not prevented.” |
| Render is sleeping/restarting | Allow brief warmup; switch to local launcher if needed | “The free host is recovering. Here is the same code on five local processes, clearly labelled local.” |
| Colab runtime quota/disconnect | Use local demo; never fake green cards | “These cards reflect actual agent telemetry. Colab is temporary compute, not a hosting SLA.” |
| Destination evidence missing | Show failed run, check logs, retry after reset | “We require signed evidence from the destination. A dropped packet is not proof of authorization enforcement.” |
| All cloud connectivity lost | Show saved **rehearsal** JSON/screenshots; run local if available | “This is recorded rehearsal evidence, not live telemetry.” |
| Time short | Run full sequence; inspect one prevented event per control | Skip deliberate disconnect and code walkthrough; retain scope caveats |

Never edit the database, preload green statuses or relabel rehearsal artifacts as live to rescue a presentation.

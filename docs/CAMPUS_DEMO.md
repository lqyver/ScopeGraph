# Campus workshop demo

This runbook turns ScopeGraph into a short, reproducible security-engineering
workshop. It is designed for a classroom, student club, or GitHub Campus
Experts event and uses only local fixture data. No public target, real domain,
credential, or third-party scan is needed.

## Learning outcomes

By the end of the session, participants should be able to:

1. Explain why a discovered domain is a candidate rather than proof of
   authorization.
2. Trace an all-in-one collection flow from enterprise discovery through
   Scope confirmation, asset inventory, review, and export.
3. Distinguish live progress, partial success, provenance, and unverified
   findings from confirmed vulnerabilities.
4. Connect a local MCP client and request a bounded, read-only asset snapshot.
5. Identify the safety controls that keep active collection explicit and scoped.

## Before the session

Use a clean checkout with Docker Desktop and Docker Compose v2. Do not place
.env files, API keys, proxy credentials, real target names, or previous scan
outputs in the repository.

On Windows, validate the local command and Compose file without starting
services:

```powershell
cmd.exe /d /c "Start-ScopeGraph.cmd --offline-check --no-open"
```

Start the local stack only after the preflight succeeds:

```powershell
Copy-Item .env.example .env
.\Start-ScopeGraph.cmd --no-open
```

The normal startup may build images or use a local Docker cache. If the event
must be completely offline, prepare the images in advance and do not start a
build that would need to download packages.

## 30-minute walkthrough

### 1. Establish the boundary (5 minutes)

Create a project with a synthetic name such as Campus Fixture Lab. Explain
that the project is local and that authorization is a deliberate input, not
something inferred from a search result.

Open **Enterprise Discovery** and select the explicit `fixture` mode. Point out:

- each source has its own persisted status and diagnostic;
- a source failure is different from a completed source with zero candidates;
- candidate evidence is reviewable, but it does not authorize active testing.

### 2. Follow the asset funnel (10 minutes)

Use the fixture candidate to walk through the human Scope confirmation step.
Then open the Scope, Assets, Network, Websites, Findings, History, and Export
views. Ask participants to find:

- where a domain, IP, port, service, website, and technology are linked;
- which values include provenance or an observation timestamp;
- how partial completion is surfaced while a run is still progressing;
- which items are explicitly marked as fixture evidence or unverified.

Do not start a real scan during a public workshop. If an authorized private lab
is used separately, record that authorization outside the public repository and
keep the scope narrow.

### 3. Use the MCP interface (10 minutes)

Configure a local MCP client with:

```json
{
  "mcpServers": {
    "scopegraph-community": {
      "type": "http",
      "url": "http://127.0.0.1:18001/mcp"
    }
  }
}
```

The agent can begin with `scopegraph_get_started`; the response describes
health, visible projects, permissions, safety boundaries, and the recommended
call order. Follow with `scopegraph_all_in_one_snapshot` to retrieve a bounded
project-wide view without reading repository documentation first.

Keep `SCOPEGRAPH_MCP_ALLOW_SCAN_START` disabled for a workshop. The default MCP
surface is read-only and cannot approve Scope, start Deep/Custom/full-port
collection, or run Nuclei.

### 4. Debrief (5 minutes)

Ask each participant to answer:

- What would have to be confirmed before an active check is allowed?
- Which result would be useful to investigate, but is not yet a vulnerability?
- Which evidence would you preserve so another person can reproduce the result?

## Evidence to record for a Campus Experts application

Keep a short private event log rather than publishing participant data:

- date, venue, and approximate attendance;
- agenda and learning outcomes;
- number of people who completed the fixture walkthrough;
- anonymous feedback or a short before/after question;
- links to public issues, pull requests, translations, or fixture improvements
  created after the session;
- one paragraph describing what changed in the project because of community
  feedback.

Do not publish names, emails, screenshots of real targets, raw scan output, or
claims that the workshop found a real vulnerability.

## Reset after the session

Stop the stack without deleting stored data:

```powershell
docker compose down
```

Use `docker compose down -v` only when deleting the local database and queue
volumes is intentional. Review `git status` and remove any local .env,
logs, exports, or screenshots before sharing the checkout.

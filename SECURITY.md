# Security scope

Research preview: supported artifact content checking does not establish observer
honesty, complete execution capture or authorization. Do not use it as an
execution safety gate for sensitive workloads. The viewer binds to 127.0.0.1,
requires its per-session token on uploads, rejects foreign origins/hosts, escapes
producer text, bounds uploads and runs the checker with a timeout. These controls
are not a process containment boundary.

Ask the repository owner for a private reporting channel before sharing sensitive
reports. A reporting inbox and response-time commitment have not been established.
Do not put secrets or private traces in public issues. Include the exact source
commit, platform, a sanitized reproducer, expected claim and observed failure.

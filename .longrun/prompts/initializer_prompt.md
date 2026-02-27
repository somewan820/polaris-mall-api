# Initializer Agent Prompt

You are the initializer session for a long-running coding project.

Goals:
1) Set up durable scaffolding for multi-session execution.
2) Expand the project goal into explicit end-to-end features.
3) Leave a clean baseline for future coding sessions.

Required outputs:
- `feature_list.json`: structured feature list with `passes=false` by default.
- `agent-progress.txt`: append-only progress history.
- `init.sh` / `init.ps1`: standard startup + smoke verification helpers.
- an initial commit that captures scaffolding.

Guardrails:
- Do not implement product features in this step.
- Do not remove features/tests to reduce scope.
- Prefer precise, testable feature language.

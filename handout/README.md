# handout/ -- consumer-facing documents (grab point)

REAL COPIES of the canonical docs in ../docs/, refreshed on every docs/ change (see the drift test
in tests/agent-guide.bats -- a stale copy fails the suite):

- ORCHESTRATOR-GUIDE.md -- the service-orchestrator contract (DRAFT/PROPOSED until features land)
- AGENT-GUIDE.md     -- the drvpsctl agent guide (shipped, drift-tested)

Refresh after editing docs/:
    install -m 0644 -T docs/ORCHESTRATOR-GUIDE.md handout/ORCHESTRATOR-GUIDE.md
    install -m 0644 -T docs/AGENT-GUIDE.md    handout/AGENT-GUIDE.md
or generate a timestamped standalone agent handout:
    bash bin/make-pack.sh --profile=agent

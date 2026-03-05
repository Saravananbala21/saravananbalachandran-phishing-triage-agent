\# SOC Phishing Triage Agent (Agentic AI)



A Demo-ready \*\*SOC Phishing Triage Agent\*\* that automates \*\*L1 phishing triage\*\* using a multi-agent workflow:

\*\*Classifier → Evidence Collector → Response Agent → Risk Scoring\*\*, with a Streamlit SOC console UI.



> Current mode: \*\*Offline demo\*\* using sample JSON alerts (Defender-like).  

> Next: swap ingestion/enrichment to Microsoft Defender / Graph Security APIs.



---



\## What this solves



SOC teams spend large effort on repetitive phishing alert triage. This project automates:



\- \*\*Classification\*\* (Benign / Suspicious / Malicious)

\- \*\*Evidence collection\*\* (deterministic extraction + checks)

\- \*\*Recommended response actions\*\* (SOC runbook style)

\- \*\*Risk scoring\*\* (0–100)

\- \*\*SOC tier handoff\*\* (L1 / L2 / L3 responsibilities shown in UI)



---



\## Demo UI (SOC Console)



Run locally and open in browser (localhost).



\- Left: \*\*Alert inbox\*\*

\- Middle: \*\*Agent stages\*\*

\- Right: \*\*Risk score + Actions + L1/L2/L3 handoff\*\*



---



\## Architecture (high level)



\*\*Ingestion → Orchestration → Intelligence → Response\*\*



\- \*\*Ingestion:\*\* sample JSON alerts (future: Defender XDR / Graph Security)

\- \*\*Orchestration:\*\* LangGraph workflow (multi-step triage pipeline)

\- \*\*Intelligence:\*\* OpenAI model + playbook-guided reasoning (LangChain-style prompting)

\- \*\*Response:\*\* Streamlit UI + structured report artifact



---



\## Agent workflow



\*\*Alert Input\*\*

→ \*\*Classifier Agent\*\* (LLM decision using playbook)

→ \*\*Evidence Collector\*\* (deterministic extraction + signals)

→ \*\*Response Agent\*\* (recommended actions)

→ \*\*Risk Score\*\*

→ \*\*SOC Handoff (L1/L2/L3)\*\*

→ \*\*Report saved\*\* (`data/output/triage\_report\_streamlit.json`)



---



\## Repo structure



\- `app.py`  

&nbsp; Streamlit UI + orchestration glue for the demo. Loads alerts, runs agents, renders stage-by-stage output.



\- `agents/phishing\_classifier.py`  

&nbsp; LLM classifier: uses playbook + alert fields to produce classification, confidence, and indicators.



\- `agents/evidence\_collector.py`  

&nbsp; Deterministic evidence: domain extraction, internal/external checks, URL/attachment signals.



\- `agents/response\_agent.py`  

&nbsp; Produces SOC runbook-style recommended actions based on classification/evidence.



\- `workflows/`  

&nbsp; LangGraph workflow orchestration (pipeline graph). (Expands easily to branching flows.)



\- `playbooks/phishing\_triage\_playbook.md`  

&nbsp; Triage playbook used as the decision framework.



\- `data/sample\_alerts/`  

&nbsp; Sample Defender-like JSON alerts for offline testing.



---



\## Run locally



\### 1) Create venv + install dependencies

```bash

python -m venv venv

.\\venv\\Scripts\\activate

pip install -r requirements.txt


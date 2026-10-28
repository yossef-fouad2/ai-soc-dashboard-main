# Local Hybrid SOC Investigation Workbench

A single-analyst research prototype implementing the saved hybrid SOC proposal plan. It ingests supplied recorded network flows and an OpenSSH authentication sample, runs independent event-time rules and a normal-trained Isolation Forest, and retains evidence, alert dispositions and manual investigations in SQLite.

Detections are **suspected activity**, not confirmed compromise. Severity is investigation priority, not confidence. Network anomaly margins are not attack probabilities or attack-name predictions. This is not a production SIEM, live collector or multi-user service.

## Setup

Run these commands from `ai-soc-dashboard-main` using Python 3.12. The existing dependency pins were retained and tested with Python 3.12.6; only upload/test dependencies were added.

```powershell
python -m pip install -r requirements.txt
python backend/sources.py
python backend/ingestion.py
python backend/train.py
python -m uvicorn main:app --app-dir backend --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000/**. HTML, CSS, JavaScript and the API are served from the same origin; no separate frontend server or external chart/font library is required.

- `sources.py` installs the public OpenSSH sample only after validating its pinned checksum and requiring its retained license notice. It never overwrites an existing different file.
- `ingestion.py` profiles both supplied corpora and writes `evaluation/data_profile.json` without modifying the inputs.
- `train.py` explicitly fits/calibrates the new network model and writes held-out evaluation results. Training can take several minutes, primarily for partition checks and event-time rules.
- Training is optional for authentication and rule-only operation. If `models/network_model.pkl` is missing, incompatible or fails inference, source-appropriate rules still run and the missing ML is reported explicitly.
- Startup, health checks, imports, analysis and refresh never train a model. Do not run the legacy data generators as part of this workflow.
- Keep the server on loopback with one Uvicorn worker. The app has no user authentication or production job infrastructure. Do not bind it to the internet or use multiple workers against its recovery state.

The working bare-import layout is intentional: use `--app-dir backend` for Uvicorn and `-o pythonpath=backend` for pytest rather than adding production `sys.path` patches.

## Analyst Workflow

1. Select a reference preset and **Import Preset**, or import one supported `.csv`, `.log` or `.txt` file. Preview includes provenance, raw/eligible/skipped counts, rejection reasons and clock warnings. Importing does not start analysis.
2. Select the imported dataset, optionally change detection configuration, then press **Run Analysis**. A finite dataset/config/rule/model snapshot moves through `pending`, `running`, `completed` or `failed`. Only one analysis can be active at a time.
3. Read severity/activity charts and filter the paginated queue by priority, suspected activity, method, disposition and IP/account/host/title. Summary counts cover all matching persisted alerts, not just the visible page. Raw and normalized event totals are separate from grouped alert totals.
4. Open any priority level to inspect rule thresholds, counts, ports, model version, calibrated margins, raw examples and lossless physical source-line ranges. **All Supporting Events** retrieves every retained normalized raw record 25 at a time.
5. Save an alert disposition (`new`, `investigating`, `resolved`, `false_positive`). Check same-run alerts to create a manual incident; edit its title, notes, status (`open`, `investigating`, `closed`) and membership. Grouping is analyst-led, never automatic evidence of correlation.

Refresh and page reload only read stored state. Repeating an identical completed snapshot returns the same run/alert IDs and retains analyst edits; changed configuration or model artifact creates a comparable new snapshot. A restart marks interrupted pending/running runs failed without partial alerts and permits an explicit retry.

Optional **Request Optional Explanation** calls the configured Ollama service only on that button press. `OLLAMA_URL` defaults to `http://localhost:11434/api/generate`; `OLLAMA_MODEL` defaults to `mistral`. Ollama is not required for ingestion, detection, evidence, charts or cases. Generated prose is displayed as untrusted, non-evidence commentary and never changes detections or dispositions.

## Supplied Sources

| Source | Raw Records | Bytes | Purpose |
| --- | ---: | ---: | --- |
| `data/tcp_complete.csv` | 123,332 | 82,014,921 | Completed TCP exporter observations |
| `data/tcp_nocomplete.csv` | 154,877 | 41,286,125 | Incomplete TCP exporter observations, not authentication outcomes |
| `data/udp_complete.csv` | 99,495 | 24,785,220 | UDP observations, including absent-direction epoch zeros |
| `data/OpenSSH_2k.log` | 2,000 | 225,216 | Unlabeled recorded authentication/parser/rule demonstration |

The network preset has **377,704 raw records / 377,702 eligible observations**, after removing two exact exporter-observation duplicates and retaining all duplicate provenance. No required-field rows were rejected in the supplied network files; exported formatted timestamps match their source epochs within 1 ms. Profiles include full headers, selected columns, missing/invalid values, label/date counts, valid zero values and absent UDP directions.

The OpenSSH sample has **518 explicit failed-password attempts and one accepted-password attempt**, for **519 eligible events / 1,481 ignored non-attempt lines**. PAM notices, invalid-user notices and compressed retry summaries do not become additional individual attempts. Summary text and represented repetition counts remain in provenance; repeated explicit attempts are not deduplicated. Its accepted login is at physical line 956 and does not meet the configured same-identity failure-burst condition, so it is not falsely presented as a suspicious success.

### Clock And Schema Handling

- CSV transport and observation state come from validated exporter schemas, never filenames, roles or attacker identities. The leading `#` TCP/UDP header is preserved, not interpreted as a comment.
- Network epochs are milliseconds interpreted as UTC. TCP duration uses `durat:31`; UDP duration spans the earliest populated directional first time to the latest populated directional end, ignoring absent-direction epoch zero. Two normalized UDP starts are on January 20 because their server direction precedes their January 21 client timestamp; split-boundary checks exclude them from the experiment.
- Required addresses, ports and numeric magnitudes are validated; malformed, negative, non-finite or unsafe values are reported as rejected rows. Legitimate zero bytes, packets and duration remain eligible. Empty/all-invalid sources fail explicitly, not as normal activity.
- OpenSSH recorded timestamps are December 10, 06:55:46-11:04:45, with **unknown capture year and timezone**. The parser preserves those strings and uses an explicitly source-relative clock for windows. It must not be aligned with AIT UTC or presented as an independently timestamped attack timeline.

### Provenance And Notices

**AIT Netflow Data Set**, DOI [10.5281/zenodo.6610489](https://zenodo.org/records/6610489), published June 3, 2022, by Francesca Soro, Max Landauer, Florian Skopik, Wolfgang Hotwagner and Markus Wurzenberger. The record declares [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). These are recorded **simulated enterprise testbeds**, extracted with Tstat from AIT-LDS-v2.0, not production-network observations. The supplied local byte hashes are recorded in profiles and model metadata; normalized outputs, filtering, deduplication and models are derived modifications, not publisher-endorsed results.

The upstream [AIT-LDS-v2.0 record](https://zenodo.org/records/5789064) separately declares CC BY-NC-SA 4.0. Do not apply the Netflow record's license to upstream packet captures/logs; the differing declarations do not independently resolve their underlying licensing authority. AIT requests citations to [Maintainable Log Datasets for Evaluation of Intrusion Detection Systems](https://doi.org/10.1109/TDSC.2022.3201582) and [Have It Your Way: Generating Customized Log Datasets With a Model-Driven Simulation Testbed](https://doi.org/10.1109/TR.2020.3031317); its processing README additionally references the Trevisan et al. 2017 Tstat paper.

**Loghub OpenSSH**, [repository](https://github.com/logpai/loghub), [sample](https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log), [immutable pinned sample](https://raw.githubusercontent.com/logpai/loghub/374038faa4ca122dd7ca0730372c0b78f76f8597/OpenSSH/OpenSSH_2k.log). SHA-256: `1e4912727fa88245113d41b16a0cd25ceadba7f931e1c406542885b91254264f`. The source says the full logs came from an OpenSSH lab server; the full 28.4-day corpus is not the 2,000-line sample. Companion EventIds are message-template labels, not attack ground truth.

The actual Loghub research/academic notice is retained in **`data/Loghub-LICENSE.txt`**, including its requirement to include that notice in all dataset copies. It is not the MIT or OpenSSH software license, and unrestricted commercial reuse is not established. Refer to the repository and cite Jieming Zhu, Shilin He, Pinjia He, Jinyang Liu and Michael R. Lyu, *Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics*, ISSRE 2023, where applicable; retain the repository's current [citation guidance](https://raw.githubusercontent.com/logpai/loghub/master/CITATION), also referencing Loghub-2.0, ISSTA 2024.

## Detection And Model

| Rule | Initial Configuration | Evidence |
| --- | --- | --- |
| Suspected authentication brute force | At least 5 explicit failures in 300 seconds | Same source IP, account, host, dataset and source clock |
| Suspected port scan | At least 20 distinct destination ports in 60 seconds | Same source/destination pair and transport; tiny/zero-payload probes remain eligible |
| Suspicious accepted login | Accepted password/publickey within 300 seconds after the configured failure burst | Same identity/host/source clock; accepted outcome is not proof of compromise |

Window boundaries are inclusive. Cooldowns summarize continuing bursts without losing occurrences, last seen or references; their effective minimum is the corresponding detection window. Authentication bypasses the network model. The earlier generic byte-spike/UDP-flood checks are retired rather than called reliable DoS detectors, and incomplete TCP or publisher DNS enumeration labels are never treated as failed passwords.

The network Isolation Forest uses exactly six features: directional client/server bytes, directional client/server packets, duration in milliseconds, and validated transport code (`TCP=0`, `UDP=1`). Five nonnegative magnitudes use deterministic per-row `log1p`; transport is not batch-normalized. Labels, roles, IPs, timestamps and source names are not model inputs. A row's transformation, score and prediction are invariant to its surrounding batch.

The [publisher labeling notebook](https://zenodo.org/api/records/6610489/files/2_label_logs.ipynb/content) supplies a versioned exact benign/attack-related label whitelist for evaluation and baseline selection. Unrecognized/blank/conflicting annotations remain unknown, not benign, and are excluded from normal fitting, calibration and metric denominators. Role alone does not determine a label: `benign DNS - attacker requesting updates` is explicitly publisher-benign. Publisher TCP labels use role/port/time heuristics; UDP `data exfiltration` is a residual assignment even on January 21-23, so earlier dates cannot alone establish a clean baseline.

Explicit fitting/calibration uses seed 42, 300 trees, maximum 2,048 training samples per tree, one job, and these UTC partitions:

| Partition | Selection | Eligible Records Used |
| --- | --- | ---: |
| Fit | January 21-22, exact publisher-benign labels only | 108,858 |
| Threshold calibration | January 23, exact publisher-benign labels only | 54,561 |
| Held-out experiment | January 24, mixed known publisher labels | 199,385 |

Exact duplicates are removed before splitting; 61 boundary-spanning flows are excluded, and overlapping same-5-tuple components spanning partitions would also be excluded. There is no random temporal split or fallback to unknown/attack-labeled normal training. The initial 1% normal-validation false-alert budget yields **0.9989% observed validation FPR**, threshold **-0.6682603635419561**. Positive `threshold - score_samples` margin means anomalous, not a probability. Features and calibration are fixed before the held-out period; do not tune them on these final test results.

`models/network_model.pkl` is the new versioned artifact; `evaluation/model_metadata.json` records feature/order/transform versions, partitions, source hashes, seed, threshold, fitting parameters and scikit-learn version. Only this trusted code-configured local artifact is loaded. Missing/legacy/incompatible artifacts are rejected; uploads cannot provide a model or choose a model path. Changed artifact identity refreshes the cache. **`models/model.pkl` and `data/logs.csv` remain untouched**, and the proposal DOCX was not edited. Legacy `frontend/app.py` is retained as reference, not the final interface.

## Measured Results

The frozen publisher-label experiment is in **`evaluation/network_evaluation.json`**, including confusion matrices, per-protocol/per-label detections and misses, timing and complementary examples. These are results against **simulated-testbed publisher annotations**, not independently adjudicated attacks or production accuracy.

Per-flow ML on 199,385 held-out observations: TP 154,804, FP 486, FN 1,387, TN 42,708; **precision 99.69%, recall 99.11%, F1 99.40%, FPR 1.13%**.

For an apples-to-apples comparison, all methods are also measured over the same **64,824 fixed 60-second source/destination/transport groups**. A known group is attack-related if any member has a known attack annotation; groups containing unknown annotations are excluded. These are evaluation units, not notification counts.

| Method | Precision | Recall | F1 | Normal-Group FPR |
| --- | ---: | ---: | ---: | ---: |
| Network rules only | 100.00% | 0.04% | 0.08% | 0.00% |
| ML only | 99.26% | 99.46% | 99.36% | 3.31% |
| Combined | 99.26% | 99.47% | 99.36% | 3.31% |

The rule's deliberately narrow port-scan coverage must not be confused with broad network detection. Model evidence outside that rule is demonstrated, for example, by **`tcp_complete.csv` physical line 42,254**, UTC `2022-01-24T03:59:43.647681Z`: 153 client bytes, 139,922,493 server bytes, 8,320/12,529 packets, 2,544.302 ms duration and positive margin 0.107897. The original publisher annotation `online_cracking` is evaluation context; the model reports **network anomaly**, not that attack name. The saved demo network incident links directly to this inspectable record.

Important remaining gaps: all **941 UDP records labeled exfiltration**, all 90 `dirb_scan` records and all 76 `wpscan` records are missed by this model. Detection of `host_discover_local` dominates the aggregate result, and rare benign classes such as OpenVPN and incomplete benign flows have high false-alert rates. These weaknesses and the heuristic label provenance prevent production-accuracy claims. Authentication has no independent attack labels: its parser/rules are verified with controlled boundary cases and sample evidence, not measured attack-detection accuracy. Extending features or training requires a new validation-led experiment and an untouched final test period.

Actual all-source API runs retain **54,365 grouped network alerts** (10 rule+ML port-scan bursts and 54,355 model-only anomaly groups) and **9 authentication failure bursts**. They are not per-flow predictions or the independent held-out test. The first full network import/analysis workflow took about 135 seconds on this environment; a reused snapshot only revalidates the imported preset and reads saved results. After indexing, a 25-row queue read took about 0.20 seconds and its all-matching summary about 0.025 seconds on the 54,365-alert corpus. Large volumes remain a practical research-prototype limitation, not evidence that all notifications merit action.

## Supervised TCP Experiment

`backend/supervised.py` adds a **separate supervised TCP candidate**, not a replacement for the dashboard's Isolation Forest. It learns publisher-benign versus attack-related labels with a Random Forest, traffic ratios, TCP counters and trailing 60-second source/service histories. Identities are only grouping keys; labels, roles, raw addresses, absolute timestamps and capture names are not model features. Histories use strictly earlier flow completion times, not future flows or other captures. End time approximates record availability; this is not a claim of live detection latency.

The initial candidate fits **278,209 TCP flows from the whole Russellmitchell capture**, including January 24. Fox's **184,521 TCP flows** are development/validation data used to choose the alert threshold, maximizing F1 subject to at least 50% precision and at most 1% benign FPR. Neither January 24 nor Fox is an untouched candidate test. UDP's residual exfiltration labels are outside this candidate's scope.

**Santos was selected before fitting, downloaded only after the model and threshold were frozen, and not used for tuning.** The pinned 25.7 MB archive is installed separately in `data/experiments/santos/`, with publisher checksum, per-file SHA-256, citation and CC BY 4.0 provenance. No input files or original model/evaluation artifacts are overwritten. The evaluated population is **184,508 known-label TCP flows**; four eligible TCP flows with unknown labels are excluded from both models' metrics, and ten malformed TCP rows are rejected by the shared parser.

| Santos Held-Out TCP | Precision | Recall | F1 | Benign FPR |
| --- | ---: | ---: | ---: | ---: |
| Frozen Isolation Forest | 72.90% | 89.75% | 80.45% | 1.11% |
| Supervised candidate | **94.22%** | **94.84%** | **94.53%** | **0.19%** |

Candidate test confusion matrix: **TP 5,627 / FP 345 / FN 306 / TN 178,230**, accuracy **99.65%**. These are per-flow publisher-label results on one simulated testbed, not universal or production attack accuracy. The candidate also has additional labeled training data, so improvement cannot be attributed to the algorithm alone.

Fox validation precision/recall/F1 changed from **7.37% / 1.48% / 2.47%** to **98.43% / 96.51% / 97.46%**. The candidate flagged 8,246/8,256 directory-scan-labeled Fox flows, versus 4 for the baseline. **These Fox numbers are validation results, not a fresh final test.** On Santos the corresponding directory-scan counts are 90/90 versus 0/90; that small class support does not prove general coverage.

The saved artifact is `evaluation/supervised_v1/candidate.pkl`; the full audit, populations, per-label misses and same-population baseline comparison are in `evaluation/supervised_v1/comparison.json`. The dashboard's **Run Analysis still uses the existing Isolation Forest**; no classifier predictions are silently substituted into old anomaly alerts. This candidate is appropriate for a separate TCP demonstration and further validation, not automatic deployment.

To score the saved Santos TCP capture without retraining, from the project directory, choose a new output directory:

```powershell
python backend/supervised.py --score-only data/experiments/santos/tcp_complete.csv data/experiments/santos/tcp_nocomplete.csv --output-dir evaluation/presentation_run
```

This writes `predictions.csv` and `scoring.json`, preserving both models and the selected threshold. Only load a **trusted local** candidate pickle. Supply full recorded histories: random row sampling changes contextual features. Scoring training/development data does not turn it into an independent test.

To repeat the explicitly versioned experiment into a **new** output directory:

```powershell
python backend/supervised.py --validation data/imports/f29bdfc5b55d44f78524d5ac206124b1.csv data/imports/99456569c2584bc98a0cb8d849f7559b.csv --test-santos --output-dir evaluation/supervised_repeat
```

Existing output directories are refused, constraints are not relaxed when validation fails, and a failed validation candidate does not consume the Santos test. Once Santos results inform any model changes, use a different untouched capture for the next final test. Authentication and UDP behavior remain unchanged.

## Validation

```powershell
python -m pytest -o pythonpath=backend
node --check frontend/dashboard.js
python -m pip check
```

Verified: **808 controlled tests passed**; the expensive real-preset test is skipped by default and was executed separately:

```powershell
$env:SOC_REAL_PRESET_TESTS = '1'
python -m pytest -o pythonpath=backend tests/test_real_presets.py -s
Remove-Item Env:SOC_REAL_PRESET_TESTS
```

That real test passed actual corpus counts, ML-only evidence, original file hashes, idempotent snapshots, source references, pagination, manual state and restart persistence. It writes `evaluation/preset_acceptance.json`. Two warnings come from the installed Starlette multipart/AnyIO imports; `pip check` reports no broken requirements.

Optional served browser tests use a **new isolated SQLite copy** of the populated real-preset state, keeping controlled hostile-text fixtures out of the analyst's main database. First run the real-preset acceptance above, then start this test server in a separate terminal:

```powershell
python -m pip install playwright
python -m playwright install chromium
$env:PYTHONPATH = 'backend'
python -m uvicorn browser_server:app --app-dir tests --host 127.0.0.1 --port 8001
```

```powershell
python tests/browser_check.py --base-url http://127.0.0.1:8001
```

Verified in Chromium 156 at 1440x1050 desktop and 390x844 mobile: real presets, accurate filtered counts beyond one page, raw-event pagination, evidence at all priorities, no horizontal overflow/JavaScript errors, escaped hostile account/host/notes, explicit-only analysis, GET-only refresh, persisted statuses/membership, empty/read-error states and unavailable optional Ollama without losing evidence. Screenshots and `browser_acceptance.json` are generated in `evaluation/browser/`.

## Safety And Files

- Uploads are bounded at **128 MiB per file / 500,000 records per source**, measured against the largest supplied file (82,014,921 bytes) and largest source count (154,877). The three-file preset totals 148,086,266 bytes; the byte cap is per source, not a sum/truncation rule.
- Plain filenames, recognized schemas, generated private upload paths and exclusive creation prevent traversal/overwrites. Streamed multipart and JSON bodies are bounded before parsing, including chunked input; cross-origin mutations are rejected by a pure-ASGI guard.
- SQLite connections are task-local, foreign keys are enabled, and run/evidence/count publication is atomic. Queue and summary queries are indexed and do not fetch full evidence payloads into list pages.
- Only the three fixed browser assets are served. Raw data, model artifacts, the legacy frontend, upload directories and the database are not static downloads. Untrusted text is rendered with DOM text APIs; a same-origin CSP adds defense in depth.

| Location | Purpose |
| --- | --- |
| `backend/ingestion.py`, `sources.py` | Shared immutable-source parsers, profiles and pinned sample installation |
| `backend/rules.py`, `preprocessing.py`, `detection.py`, `train.py`, `evaluation.py` | Configurable rules, deterministic features, trusted artifact inference, explicit fit/calibration/experiment |
| `backend/agents.py`, `severity.py` | Independent detection composition and evidence-backed investigation priority |
| `backend/storage.py`, `main.py`, `llm.py` | Atomic persisted API and optional on-demand commentary |
| `frontend/index.html`, `styles.css`, `dashboard.js` | Final responsive same-origin investigation console |
| `state/soc.sqlite3` | Private persisted datasets/imports/runs/alerts/all supporting events/incidents |
| `data/imports/` | Generated private validated uploads; original supplied inputs are not overwritten |
| `evaluation/`, `models/network_model.pkl` | Generated profiles/metrics/acceptance artifacts and trusted model, ignored in version control |
| `tests/` | Controlled parser/rule/model/storage/API cases and opt-in real/browser acceptance |

# ClickFix Threat Hunting — Test Dataset

## Overview

This repository contains the synthetic test dataset used to evaluate the KQL detection queries and validate the threat hunting model developed in the master's thesis *"Threat Hunting Model for ClickFix Technique in Enterprise Environments"* by Aytan Khalilova.

The dataset is synthetic — generated to match the Microsoft Defender for Endpoint (MDE) Advanced Hunting schema — because no publicly available dataset with real MDE telemetry exists. Real MDE exports contain enterprise PII and cannot be published. All command-line arguments in attack entries are sourced directly from the threat intelligence reports cited in the thesis.

---

## Files

| File | Purpose | Rows |
|---|---|---|
| `clickfix_DeviceProcessEvents.csv` | Import into Sentinel as `DeviceProcessEvents_CL` | 121 |
| `clickfix_DeviceRegistryEvents.csv` | Import into Sentinel as `DeviceRegistryEvents_CL` | 29 |
| `clickfix_DeviceNetworkEvents.csv` | Import into Sentinel as `DeviceNetworkEvents_CL` | 28 |
| `clickfix_DeviceFileEvents.csv` | Import into Sentinel as `DeviceFileEvents_CL` | 3 |
| `clickfix_kql_test_manifest.csv` | Verify KQL query results — maps each ReportId to its Classification (TruePositive or Benign) | 181 |
| `clickfix_model_validation_manifest.csv` | Verify model validation — maps each of the 14 model scenarios to its dataset entries via ReportId | 14 |
| `clickfix_artifact_recovery_manifest.csv` | Verify artifact recovery rates — maps each ReportId to its ArtifactType per model scenario | 30 |

---

## Dataset Composition

**Total: 181 log entries across 130 scenarios.**

- **30 attack scenarios → 81 log entries** — each attack scenario generates between 1 and 4 correlated log entries across multiple tables, reflecting the multi-table join design of the KQL detection queries
- **100 benign scenarios → 100 log entries** — each benign scenario produces one log entry representing legitimate enterprise activity


---

## How to Use

### Step 1 — Import into Microsoft Sentinel

Create four custom log tables in your Sentinel workspace and upload each CSV. For full instructions on creating custom log tables in Microsoft Sentinel, refer to the official Microsoft documentation: [Collect logs from text files with Azure Monitor Agent and ingest to Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/connect-custom-logs-ama).

| CSV File | Sentinel Table Name |
|---|---|
| `clickfix_DeviceProcessEvents.csv` | `DeviceProcessEvents_CL` |
| `clickfix_DeviceRegistryEvents.csv` | `DeviceRegistryEvents_CL` |
| `clickfix_DeviceNetworkEvents.csv` | `DeviceNetworkEvents_CL` |
| `clickfix_DeviceFileEvents.csv` | `DeviceFileEvents_CL` |

Update the KQL queries from the thesis by replacing `DeviceProcessEvents` with `DeviceProcessEvents_CL` (and equivalently for the other three tables).

### Step 2 — Verify KQL Query Results

After running a query, take the `ReportId` from any result and look it up in `clickfix_kql_test_manifest.csv`:

| Column | Description |
|---|---|
| `ReportId` | Links the log entry to its classification |
| `Table` | Which MDE table the entry belongs to |
| `Scenario` | Scenario ID (TP-01, FP-21 etc.) |
| `Classification` | TruePositive or Benign |
| `DeviceName` | Device the entry belongs to |
| `AccountName` | User account |
| `Timestamp` | Event timestamp |

A result where `Classification = TruePositive` confirms the query correctly detected an attack scenario. A result where `Classification = Benign` is a false positive.

### Step 3 — Verify Model Validation Results

Use `clickfix_model_validation_manifest.csv` to verify the 14 model validation scenarios. Each scenario is identified by its `ModelScenarioId` (MV-01 through MV-14) and linked to its dataset entries via `ReportIds`.

| Column | Description |
|---|---|
| `ModelScenarioId` | MV-01 through MV-14 |
| `ModelCategory` | Standard ClickFix Variation, State-Sponsored, or False Positive |
| `VariationCategory` | Specific ClickFix variation name |
| `DatasetScenario` | Corresponding scenario ID in the dataset |
| `LogEntryCount` | Number of log entries belonging to this scenario |
| `ReportIds` | Pipe-separated ReportIds of all log entries for this scenario |

### Step 4 — Verify Artifact Recovery Rates

Use `clickfix_artifact_recovery_manifest.csv` to verify the artifact recovery rates. Each row maps a `ReportId` to its `ArtifactType` for a specific model scenario — allowing independent verification of which artifact types were recoverable per scenario.

| Column | Description |
|---|---|
| `ModelScenarioId` | MV-01 through MV-12 (proved and partially proved scenarios only) |
| `DatasetScenario` | Corresponding scenario ID in the dataset |
| `ReportId` | Links to the raw log entry in the table files |
| `Table` | MDE table the entry belongs to |
| `ArtifactType` | Process Artifact, Registry Artifact, Network Artifact, or File Artifact |
| `DeviceName` | Device the entry belongs to |
| `AccountName` | User account |
| `Timestamp` | Event timestamp |

---

## Table Schemas

### DeviceProcessEvents_CL (121 rows)

| Column | Description |
|---|---|
| `Timestamp` | ISO 8601 event timestamp — all entries in March 2026 |
| `DeviceId` | 40-character hex device identifier |
| `DeviceName` | Corporate workstation name (CORP-WS-XXX / CORP-LT-XXX) |
| `ActionType` | ProcessCreated |
| `FileName` | Process binary filename |
| `FolderPath` | Full path of the process binary |
| `SHA1` | SHA1 hash of the process binary |
| `ProcessCommandLine` | Full command line including all arguments |
| `ProcessId` | Numeric process ID |
| `InitiatingProcessFileName` | Parent process filename |
| `InitiatingProcessId` | Parent process ID |
| `InitiatingProcessCommandLine` | Parent process command line |
| `InitiatingProcessParentFileName` | Grandparent process filename |
| `InitiatingProcessSHA1` | SHA1 hash of the parent binary |
| `AccountName` | Username |
| `AccountDomain` | Domain (CORP) |
| `AccountSid` | Windows Security Identifier |
| `ReportId` | Unique entry identifier — use to cross-reference manifests |

### DeviceRegistryEvents_CL (29 rows)

| Column | Description |
|---|---|
| `Timestamp` | ISO 8601 event timestamp |
| `DeviceId` | Device identifier |
| `DeviceName` | Device name |
| `ActionType` | RegistryValueSet |
| `RegistryKey` | Full registry key path |
| `RegistryValueName` | Registry value name |
| `RegistryValueData` | Registry value data |
| `InitiatingProcessFileName` | Process that wrote the registry value |
| `InitiatingProcessId` | Process ID |
| `InitiatingProcessSHA1` | SHA1 of the initiating process |
| `AccountName` | Username |
| `AccountDomain` | Domain |
| `AccountSid` | Windows Security Identifier |
| `ReportId` | Unique entry identifier — use to cross-reference manifests |

### DeviceNetworkEvents_CL (28 rows)

| Column | Description |
|---|---|
| `Timestamp` | ISO 8601 event timestamp |
| `DeviceId` | Device identifier |
| `DeviceName` | Device name |
| `ActionType` | ConnectionSuccess |
| `InitiatingProcessFileName` | Process that made the connection |
| `InitiatingProcessId` | Process ID |
| `InitiatingProcessSHA1` | SHA1 of the initiating process |
| `RemoteIP` | Destination IP address |
| `RemotePort` | Destination port |
| `RemoteUrl` | Destination URL |
| `RemoteIPType` | Public or Private |
| `Protocol` | Tcp |
| `LocalIP` | Source IP address of the device |
| `LocalPort` | Source port |
| `AccountName` | Username |
| `AccountDomain` | Domain |
| `AccountSid` | Windows Security Identifier |
| `ReportId` | Unique entry identifier — use to cross-reference manifests |

### DeviceFileEvents_CL (3 rows)

| Column | Description |
|---|---|
| `Timestamp` | ISO 8601 event timestamp |
| `DeviceId` | Device identifier |
| `DeviceName` | Device name |
| `ActionType` | FileCreated |
| `FileName` | Created file name |
| `FolderPath` | Full path of the created file |
| `SHA1` | SHA1 hash of the file |
| `InitiatingProcessFileName` | Process that created the file |
| `InitiatingProcessId` | Process ID |
| `InitiatingProcessSHA1` | SHA1 of the initiating process |
| `AccountName` | Username |
| `AccountDomain` | Domain |
| `AccountSid` | Windows Security Identifier |
| `ReportId` | Unique entry identifier — use to cross-reference manifests |


---


## Generation
The dataset was generated by Claude Sonnet 4.6 (claude-sonnet-4-6) as part of the thesis research process. All timestamps are in March 2026. Command-line arguments in attack entries are sourced from the threat intelligence reports cited in the thesis. 

---

## Citation

> *Threat Hunting Model for ClickFix Technique in Enterprise Environments*, Master's Thesis, Aytan Khalilova, 2026.

---

## Threat Intelligence Sources

- Proofpoint Threat Research — [*From Clipboard to Compromise: A PowerShell Self-Pwn*](https://www.proofpoint.com/us/blog/threat-insight/clipboard-compromise-powershell-self-pwn)
- Proofpoint Threat Research — [*Around the World in 90 Days: State-Sponsored Actors Try ClickFix*](https://www.proofpoint.com/us/blog/threat-insight/around-world-90-days-state-sponsored-actors-try-clickfix)
- Microsoft Threat Intelligence — [*Think Before You Click(Fix): Analyzing the ClickFix Social Engineering Technique*](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/)
- Sekoia TDR — [*From Contagious to ClickFake Interview: Lazarus Leveraging the ClickFix Tactic*](https://blog.sekoia.io/clickfake-interview-campaign-by-lazarus/)
- Elastic Security Labs — [*A Wretch Client: From ClickFix Deception to Information Stealer Deployment*](https://www.elastic.co/security-labs/a-wretch-client)
- Microsoft Threat Intelligence — [*New ClickFix Variant CrashFix Deploying Python RAT Trojan*](https://www.microsoft.com/en-us/security/blog/2026/02/05/clickfix-variant-crashfix-deploying-python-rat-trojan/)
- SOCRadar — [*ClickFix & FileFix: How a Copy-Paste Trick Became 2025's Top Social Engineering Threat*](https://socradar.io/blog/clickfix-filefix-copy-paste-top-social-engineering/)
- Push Security — [*ConsentFix: Browser-Native ClickFix Hijacks OAuth Grants*](https://pushsecurity.com/blog/consentfix) (2025)
- The Hacker News — [*New FileFix Variant Delivers StealC Malware Through Multilingual Phishing Site*](https://thehackernews.com/2025/09/new-filefix-variant-delivers-stealc.html)
- Microsoft Threat Intelligence — [*Phishing Campaign Impersonates Booking.com, Delivers Credential-Stealing Malware*](https://www.microsoft.com/en-us/security/blog/2025/03/13/phishing-campaign-impersonates-booking-com-delivers-a-suite-of-credential-stealing-malware/)

# ClickFix Threat Hunting — Dataset

## Overview

This repository contains two synthetic datasets used in the master's thesis *"Threat Hunting Model for ClickFix Technique in Enterprise Environments"*: a rule-building dataset used to develop and tune the KQL detection queries, and a test dataset used to evaluate them. The two datasets are completely separate - they share no log entries, no devices, no users, no C2 infrastructure, and no command-line content.

Both datasets are synthetic - generated to match the Microsoft Defender for Endpoint (MDE) Advanced Hunting schema - because no publicly available dataset with real MDE telemetry exists. Real MDE exports contain enterprise PII and cannot be published. All command-line arguments in attack entries are sourced directly from the threat intelligence reports cited in the thesis. 

---

## Repository Structure

```
├── build/                   # Used to develop and tune KQL queries
│   ├── clickfix_rule_DeviceProcessEvents.csv
│   ├── clickfix_rule_DeviceRegistryEvents.csv
│   ├── clickfix_rule_DeviceNetworkEvents.csv
│   ├── clickfix_rule_DeviceFileEvents.csv
│   └── clickfix_rule_dataset_manifest.csv
│
└── test/                            # Used to evaluate KQL queries and validate model
    ├── clickfix_DeviceProcessEvents.csv
    ├── clickfix_DeviceRegistryEvents.csv
    ├── clickfix_DeviceNetworkEvents.csv
    ├── clickfix_DeviceFileEvents.csv
    ├── clickfix_kql_test_manifest.csv
    ├── clickfix_model_validation_manifest.csv
    └── clickfix_artifact_recovery_manifest.csv
```

---

## Rule-Building Dataset

**Purpose:** Used to observe attack patterns and develop the seven KQL detection queries documented in Section 4.4 of the thesis.

**Period:** February 2026 | **Domain:** PROD | **Devices:** PROD-WS-01x / PROD-LT-01x

| File | Purpose | Rows |
|---|---|---|
| `clickfix_rule_DeviceProcessEvents.csv` | Import as `DeviceProcessEvents_CL` | 176 |
| `clickfix_rule_DeviceRegistryEvents.csv` | Import as `DeviceRegistryEvents_CL` | 43 |
| `clickfix_rule_DeviceNetworkEvents.csv` | Import as `DeviceNetworkEvents_CL` | 28 |
| `clickfix_rule_DeviceFileEvents.csv` | Import as `DeviceFileEvents_CL` | 3 |
| `clickfix_rule_dataset_manifest.csv` | Maps each ReportId to Scenario and Classification | 250 |

**Composition: 250 total log entries**
- 106 true positive log entries — attack scenarios covering all 9 endpoint-touching ClickFix variations and all 7 KQL query targets
- 144 benign log entries — 144 unique legitimate enterprise activity scenarios

---

## Test Dataset

**Purpose:** Used to evaluate the KQL detection queries and validate the hunting model (Section 4.6.2).

**Period:** March 2026 | **Domain:** CORP | **Devices:** CORP-WS-00x / CORP-LT-00x

| File | Purpose | Rows |
|---|---|---|
| `clickfix_DeviceProcessEvents.csv` | Import as `DeviceProcessEvents_CL` | 121 |
| `clickfix_DeviceRegistryEvents.csv` | Import as `DeviceRegistryEvents_CL` | 29 |
| `clickfix_DeviceNetworkEvents.csv` | Import as `DeviceNetworkEvents_CL` | 28 |
| `clickfix_DeviceFileEvents.csv` | Import as `DeviceFileEvents_CL` | 3 |
| `clickfix_kql_test_manifest.csv` | Verify KQL query results — Classification per ReportId | 181 |
| `clickfix_model_validation_manifest.csv` | Verify model validation — 14 scenarios (MV-01 to MV-14) | 14 |
| `clickfix_artifact_recovery_manifest.csv` | Verify artifact recovery rates — ArtifactType per ReportId | 30 |

**Composition: 181 total log entries**
- 81 true positive log entries — 30 attack scenarios covering all 9 endpoint-touching ClickFix variations
- 100 benign log entries — 100 unique legitimate enterprise activity scenarios

---


## How to Import into Microsoft Sentinel

Create custom log tables in your Sentinel workspace and upload each CSV. For full instructions refer to the official Microsoft documentation: [Collect logs from text files with Azure Monitor Agent and ingest to Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/connect-custom-logs-ama).

| Build CSV File | Test CSV File | Sentinel Table Name |
|---|---|---|
| `clickfix_[rule_]DeviceProcessEvents.csv` | `clickfix_DeviceProcessEvents.csv` | `DeviceProcessEvents_CL` |
| `clickfix_[rule_]DeviceRegistryEvents.csv` | `clickfix_DeviceRegistryEvents.csv` | `DeviceRegistryEvents_CL` |
| `clickfix_[rule_]DeviceNetworkEvents.csv` | `clickfix_DeviceNetworkEvents.csv` | `DeviceNetworkEvents_CL` |
| `clickfix_[rule_]DeviceFileEvents.csv` | `clickfix_DeviceFileEvents.csv` | `DeviceFileEvents_CL` |


---

## How to Verify Results

### KQL Query Results

After running a query, look up the `ReportId` from any result in `clickfix_kql_test_manifest.csv`:

| Column | Description |
|---|---|
| `ReportId` | Links to the raw log entry |
| `Table` | MDE table the entry belongs to |
| `Scenario` | Scenario ID (TP-01, FP-21 etc.) |
| `Classification` | TruePositive or Benign |
| `DeviceName` | Device name |
| `AccountName` | User account |
| `Timestamp` | Event timestamp |

### Model Validation Results

Use `clickfix_model_validation_manifest.csv` to verify the 14 model validation scenarios from Section 4.6.2:

| Column | Description |
|---|---|
| `ModelScenarioId` | MV-01 through MV-14 |
| `ModelCategory` | Standard ClickFix Variation, State-Sponsored, or False Positive |
| `VariationCategory` | Specific ClickFix variation name |
| `DatasetScenario` | Corresponding scenario ID in the dataset |
| `LogEntryCount` | Number of log entries for this scenario |
| `ReportIds` | Pipe-separated ReportIds of all log entries |

### Artifact Recovery Results

Use `clickfix_artifact_recovery_manifest.csv` to verify artifact recovery rates from Section 4.6.2:

| Column | Description |
|---|---|
| `ModelScenarioId` | MV-01 through MV-12 |
| `DatasetScenario` | Corresponding scenario ID |
| `ReportId` | Links to the raw log entry |
| `Table` | MDE table |
| `ArtifactType` | Process Artifact, Registry Artifact, Network Artifact, or File Artifact |
| `DeviceName` | Device name |
| `AccountName` | User account |
| `Timestamp` | Event timestamp |

---

## Table Schemas

### DeviceProcessEvents_CL

| Column | Description |
|---|---|
| `Timestamp` | ISO 8601 event timestamp |
| `DeviceId` | 40-character hex device identifier |
| `DeviceName` | Corporate workstation name |
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
| `AccountDomain` | Domain |
| `AccountSid` | Windows Security Identifier |
| `ReportId` | Unique entry identifier — use to cross-reference manifests |

### DeviceRegistryEvents_CL

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

### DeviceNetworkEvents_CL

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

### DeviceFileEvents_CL

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

## Dataset Integrity

**Cross-Dataset:**
-  Zero shared ReportIds between rule-building and test datasets

---

## Generation
Both dataset were generated by Claude Sonnet 4.6 (claude-sonnet-4-6) as part of the thesis research process. Command-line arguments in attack entries are sourced from the threat intelligence reports cited in the thesis. 

---

## Citation

> *Threat Hunting Model for ClickFix Technique in Enterprise Environments*, M.Sc. Degree of Computer Science, Cybersecurity Specialization Thesis, Aytan Khalilova,Eötvös Loránd University, 2026.

---

## Threat Intelligence Sources

- Proofpoint Threat Research — [*From Clipboard to Compromise: A PowerShell Self-Pwn*](https://www.proofpoint.com/us/blog/threat-insight/clipboard-compromise-powershell-self-pwn)
- Proofpoint Threat Research — [*Around the World in 90 Days: State-Sponsored Actors Try ClickFix*](https://www.proofpoint.com/us/blog/threat-insight/around-world-90-days-state-sponsored-actors-try-clickfix)
- Microsoft Threat Intelligence — [*Think Before You Click(Fix): Analyzing the ClickFix Social Engineering Technique*](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/)
- Sekoia TDR — [*From Contagious to ClickFake Interview: Lazarus Leveraging the ClickFix Tactic*](https://blog.sekoia.io/clickfake-interview-campaign-by-lazarus/)
- Elastic Security Labs — [*A Wretch Client: From ClickFix Deception to Information Stealer Deployment*](https://www.elastic.co/security-labs/a-wretch-client)
- Microsoft Threat Intelligence — [*New ClickFix Variant CrashFix Deploying Python RAT Trojan*](https://www.microsoft.com/en-us/security/blog/2026/02/05/clickfix-variant-crashfix-deploying-python-rat-trojan/)
- SOCRadar — [*ClickFix & FileFix: How a Copy-Paste Trick Became 2025's Top Social Engineering Threat*](https://socradar.io/blog/clickfix-filefix-copy-paste-top-social-engineering/)
- Push Security — [*ConsentFix: Browser-Native ClickFix Hijacks OAuth Grants*](https://pushsecurity.com/blog/consentfix)
- The Hacker News — [*New FileFix Variant Delivers StealC Malware Through Multilingual Phishing Site*](https://thehackernews.com/2025/09/new-filefix-variant-delivers-stealc.html)
- Microsoft Threat Intelligence — [*Phishing Campaign Impersonates Booking.com, Delivers Credential-Stealing Malware*](https://www.microsoft.com/en-us/security/blog/2025/03/13/phishing-campaign-impersonates-booking-com-delivers-a-suite-of-credential-stealing-malware/)

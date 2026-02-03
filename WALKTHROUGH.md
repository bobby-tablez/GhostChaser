# GhostChaser: Cyber Deception Walkthrough

A comprehensive guide to deploying honey tokens and canary resources for proactive threat detection in Windows environments.

---

## Table of Contents

- [Introduction](#introduction)
- [Getting Started](#getting-started)
- [Ghost Types Overview](#ghost-types-overview)
- [Ghost Accounts (Canary Users)](#ghost-accounts-canary-users)
- [Ghost Files (Canary Documents)](#ghost-files-canary-documents)
- [Ghost Shares (Honeypot Network Shares)](#ghost-shares-honeypot-network-shares)
- [Ghost SPNs (Kerberoasting Detection)](#ghost-spns-kerberoasting-detection)
- [Detection & Monitoring](#detection--monitoring)
- [Deployment Strategies](#deployment-strategies)
- [SIEM Integration](#siem-integration)
- [Troubleshooting](#troubleshooting)

---

## Introduction

**GhostChaser** is a Windows-based cyber deception toolkit designed to deploy and manage "Ghosts" - canary resources that act as tripwires across enterprise environments. These Ghosts detect unauthorized access, lateral movement, and malicious activity by triggering alerts when interacted with.

### Why Cyber Deception?

Traditional security focuses on preventing attacks. Cyber deception assumes breach and focuses on **early detection**:

| Approach | Focus | Value |
|----------|-------|-------|
| Prevention | Stop attacks before they happen | Reduces attack surface |
| Detection | Identify attacks in progress | Reduces dwell time |
| **Deception** | Detect attackers during reconnaissance | **Catches attacks before damage** |

### Key Benefits

- **Early Warning**: Detect attackers during reconnaissance, before they reach legitimate assets
- **Low False Positives**: Legitimate users never access Ghost resources - any interaction is suspicious
- **High Fidelity Alerts**: Every Ghost interaction is a strong indicator of malicious activity
- **Attacker Intelligence**: Learn about attacker TTPs based on which Ghosts they trigger

---

## Getting Started

### Prerequisites

- Windows 10/11 or Windows Server 2016+
- .NET 8.0 Runtime (or use the self-contained executable)
- Administrative privileges for deployment
- Domain Admin privileges (for domain-wide deployments)

### Installation

1. Download the latest release from the repository
2. Run `GhostChaser.exe` - no installation required
3. The application runs as a portable executable

### First Launch

1. Launch GhostChaser
2. Select the Ghost type you want to deploy
3. Configure the Ghost properties
4. Provide deployment credentials (or use current user)
5. Click "Deploy Ghost"

---

## Ghost Types Overview

GhostChaser supports four types of deception resources:

| Ghost Type | Detects | Primary Event IDs |
|------------|---------|-------------------|
| **Account** | Credential theft, brute force, lateral movement | 4624, 4625 |
| **File** | File system reconnaissance, data exfiltration | 4663, 4656 |
| **Share** | Network enumeration, lateral movement | 4663, 5140 |
| **SPN** | Kerberoasting, SPN enumeration | 4769 |

---

## Ghost Accounts (Canary Users)

Ghost Accounts are fake user accounts that trigger alerts on any authentication attempt.

### Use Cases

- Detect credential theft (Mimikatz, secretsdump)
- Detect brute force attacks
- Detect Pass-the-Hash / Pass-the-Ticket attacks
- Detect lateral movement with compromised credentials

### Configuration Options

| Field | Description | Example |
|-------|-------------|---------|
| **Username** | The account username | `svc_backup`, `admin_temp`, `sqlservice` |
| **Account Type** | Local or Domain account | Domain for enterprise |
| **Domain** | Target domain (domain accounts only) | `CORP.LOCAL` |
| **Organizational Unit** | OU path for account creation | `OU=ServiceAccounts,DC=corp,DC=local` |

### Deployment Steps

1. Select **Account (User)** as Ghost Type
2. Enter a descriptive **Ghost Name** (e.g., "Backup Service Canary")
3. Enter the **Target System** (local machine or remote hostname)
4. Configure Account Details:
   - Enter a realistic **Username** (see naming conventions below)
   - Choose **Local Account** or **Domain Account**
   - For domain accounts, specify the **Domain** and optional **OU**
5. Click **Deploy Ghost**

### Recommended Naming Conventions

Choose usernames that appear legitimate but enticing to attackers:

```
Service Accounts:
  svc_backup, svc_sql, svc_exchange, svc_admin

Admin Accounts:
  admin_temp, admin_legacy, administrator2

Database Accounts:
  dbadmin, sqlservice, oracleadmin

Application Accounts:
  app_service, iis_admin, sharepoint_svc
```

### Detection Events

| Event ID | Description | Log |
|----------|-------------|-----|
| **4624** | Successful logon (shouldn't happen - investigate immediately) | Security |
| **4625** | Failed logon attempt (credential testing detected) | Security |
| **4768** | Kerberos TGT request | Security |
| **4776** | NTLM authentication attempt | Security |

### Example SIEM Query (Splunk)

```spl
index=windows sourcetype=WinEventLog:Security
(EventCode=4624 OR EventCode=4625)
TargetUserName IN ("svc_backup", "admin_temp", "sqlservice")
| stats count by TargetUserName, IpAddress, EventCode
| where count > 0
```

---

## Ghost Files (Canary Documents)

Ghost Files are decoy documents with enticing names and realistic content that trigger alerts when accessed.

### Use Cases

- Detect file system reconnaissance
- Detect data exfiltration attempts
- Detect insider threats browsing for sensitive data
- Detect ransomware (file access patterns)

### Configuration Options

| Field | Description | Example |
|-------|-------------|---------|
| **File Path** | Location to create the file | `C:\Users\Public\Documents\` |
| **File Extension** | Type of bait file | `.txt`, `.xlsx`, `.sql`, `.config` |
| **Enable Auditing** | Configure Windows file auditing | Recommended: Yes |

### Supported File Types & Generated Content

GhostChaser generates contextually appropriate bait content:

| Extension | Content Type | Example Content |
|-----------|--------------|-----------------|
| `.txt` | Credentials document | Fake database connection strings, API keys |
| `.xlsx` | User/password list | CSV-formatted credential tables |
| `.config` | Application config | XML with connection strings, app settings |
| `.json` | Database config | Production database connection objects |
| `.sql` | Backup script | Database backup commands with server names |
| `.ps1` | PowerShell script | Admin scripts with server references |
| `.bat` | Batch file | Automated admin task scripts |

### Deployment Steps

1. Select **File (Document)** as Ghost Type
2. Enter a descriptive **Ghost Name**
3. Enter the **Target System**
4. Configure File Details:
   - Enter the **File Path** (or leave blank for default location)
   - Select the **File Extension**
   - Enable **File Auditing** (recommended)
5. Click **Deploy Ghost**

### Recommended File Names

```
Credentials:
  passwords.txt, credentials.xlsx, admin_creds.docx

Database:
  database_backup.sql, db_connection.config, prod_db.json

Configuration:
  vpn_config.txt, network_diagram.pdf, firewall_rules.xlsx

Financial:
  budget_2024.xlsx, payroll.xlsx, bank_accounts.docx
```

### Detection Events

| Event ID | Description | Log |
|----------|-------------|-----|
| **4663** | Object access (file read/write) | Security |
| **4656** | Handle requested to object | Security |
| **4658** | Handle closed | Security |

### Enabling File Auditing Manually

If GhostChaser's automatic auditing doesn't apply, enable it manually:

```powershell
# Enable auditing on a specific file
$file = "C:\Users\Public\Documents\passwords.txt"
$acl = Get-Acl $file
$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone",
    "ReadData,ReadAttributes",
    "Success,Failure"
)
$acl.AddAuditRule($auditRule)
Set-Acl $file $acl
```

---

## Ghost Shares (Honeypot Network Shares)

Ghost Shares are decoy network shares that detect reconnaissance and lateral movement.

### Use Cases

- Detect network share enumeration (net view, PowerView)
- Detect lateral movement via SMB
- Detect ransomware spreading across shares
- Detect unauthorized access attempts

### Configuration Options

| Field | Description | Example |
|-------|-------------|---------|
| **Share Name** | Name of the network share | `Backups`, `Finance`, `HR_Documents` |
| **Share Path** | Local folder path for the share | `C:\GhostShares\Finance` |
| **Description** | Share description visible in enumeration | `Financial Reports - Restricted` |
| **Enable Auditing** | Configure share access auditing | Recommended: Yes |

### Deployment Steps

1. Select **Share (Network)** as Ghost Type
2. Enter a descriptive **Ghost Name**
3. Enter the **Target System**
4. Configure Share Details:
   - Enter the **Share Name**
   - Enter the **Share Path** (local folder to share)
   - Enter a realistic **Description**
   - Enable **Share Auditing**
5. Click **Deploy Ghost**

### Auto-Generated Bait Files

Ghost Shares are automatically populated with bait files:

```
\\SERVER\Finance\
├── passwords.txt
├── credentials.xlsx
├── database_backup.sql
└── vpn_config.txt
```

### Recommended Share Names

```
Corporate:
  Finance, HR_Documents, Legal, Executive

IT:
  Backups, IT_Admin, Scripts, Configs

Sensitive:
  Confidential, Restricted, Private, Archive
```

### Detection Events

| Event ID | Description | Log |
|----------|-------------|-----|
| **5140** | Network share accessed | Security |
| **5145** | Detailed share access check | Security |
| **4663** | File access within share | Security |

### Example SIEM Query (Splunk)

```spl
index=windows sourcetype=WinEventLog:Security EventCode=5140
ShareName IN ("\\\\*\\Finance", "\\\\*\\Backups", "\\\\*\\HR_Documents")
| stats count by ShareName, IpAddress, SubjectUserName
| sort -count
```

---

## Ghost SPNs (Kerberoasting Detection)

Ghost SPNs are honey Service Principal Names that detect Kerberoasting attacks - a technique where attackers request TGS tickets for SPNs to crack offline.

### Use Cases

- Detect Kerberoasting attacks (Rubeus, Impacket GetUserSPNs)
- Detect SPN enumeration (PowerView, Kerbrute)
- Detect Active Directory reconnaissance
- Early warning of credential-based attacks

### How Kerberoasting Works

1. Attacker enumerates SPNs in Active Directory
2. Attacker requests TGS tickets for discovered SPNs
3. TGS tickets are encrypted with the service account's password hash
4. Attacker attempts offline brute-force/dictionary attacks
5. If successful, attacker gains the service account password

### Why Honey SPNs Work

- Attackers enumerate **all** SPNs - they can't distinguish honey SPNs
- Any TGS request for a honey SPN indicates attack activity
- Honey SPNs use strong passwords that won't crack offline
- Detection happens **before** the attacker succeeds

### Configuration Options

| Field | Description | Example |
|-------|-------------|---------|
| **Service Class** | SPN service type | `MSSQLSvc`, `HTTP`, `LDAP` |
| **Service Host** | Target hostname (can include port) | `sqlserver.corp.local:1433` |
| **Service Account** | Account to register SPN | `svc_sql_honey` |
| **Domain** | Target domain | `CORP.LOCAL` |
| **Create Service Account** | Create new account if needed | Recommended: Yes |

### Supported Service Classes

GhostChaser includes 20+ enticing service classes:

```
Databases:
  MSSQLSvc, oracle, postgres, mysql, mongodb, redis, elasticsearch

Web Services:
  HTTP, HTTPS, TERMSRV, WSMAN

Infrastructure:
  LDAP, CIFS, HOST, FTP, IMAP, SMTP, POP

Enterprise:
  exchangeMDB, exchangeRFR, kafka
```

### Deployment Steps

1. Select **SPN (Kerberos)** as Ghost Type
2. Enter a descriptive **Ghost Name** (e.g., "SQL Honey SPN")
3. Enter the **Target System** (domain controller or domain name)
4. Configure SPN Details:
   - Select or enter a **Service Class** (e.g., `MSSQLSvc`)
   - Enter the **Service Host** (e.g., `sqlprod.corp.local:1433`)
   - Enter the **Service Account** name (e.g., `svc_sql_backup`)
   - Enter the **Domain**
   - Enable **Create Service Account** if the account doesn't exist
   - Enable **Kerberos Auditing**
5. Click **Deploy Ghost**

### Command-Line Alternative

You can also create SPNs manually using `setspn`:

```cmd
# Create the service account first
net user svc_sql_honey P@ssw0rd123! /add /domain

# Register the SPN
setspn -s MSSQLSvc/sqlserver.corp.local:1433 CORP\svc_sql_honey

# Verify the SPN
setspn -L svc_sql_honey
```

### Detection Events

| Event ID | Description | Log |
|----------|-------------|-----|
| **4769** | Kerberos Service Ticket (TGS) requested | Security |
| **4770** | Kerberos Service Ticket renewed | Security |

### Example SIEM Query (Splunk)

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4769
ServiceName IN ("MSSQLSvc/sqlserver.corp.local:1433", "HTTP/webapp.corp.local")
| stats count by ServiceName, TargetUserName, IpAddress
| where count > 0
```

### Example SIEM Query (Microsoft Sentinel)

```kql
SecurityEvent
| where EventID == 4769
| where ServiceName has_any ("sqlserver", "webapp", "honey")
| project TimeGenerated, ServiceName, TargetAccount, IpAddress
| sort by TimeGenerated desc
```

---

## Detection & Monitoring

### Windows Event Log Configuration

Ensure these audit policies are enabled:

```powershell
# Enable Object Access auditing
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable

# Enable Logon/Logoff auditing
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable

# Enable Kerberos auditing
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
```

### Critical Event IDs Summary

| Event ID | Category | Ghost Type | Severity |
|----------|----------|------------|----------|
| 4624 | Logon Success | Account | **CRITICAL** |
| 4625 | Logon Failure | Account | HIGH |
| 4663 | Object Access | File, Share | HIGH |
| 4769 | TGS Request | SPN | **CRITICAL** |
| 5140 | Share Access | Share | HIGH |

### GhostChaser Audit Logs

GhostChaser maintains its own audit logs at:

```
C:\ProgramData\GhostChaser\Logs\GhostChaser_Audit_YYYYMMDD.log
```

Log entries are JSON-formatted for easy parsing:

```json
{
  "Timestamp": "2024-01-15T14:32:18Z",
  "EventType": "GhostCreated",
  "GhostId": "a1b2c3d4-...",
  "GhostType": "SPN",
  "GhostName": "SQL Honey SPN",
  "TargetSystem": "DC01.corp.local",
  "CreatedBy": "admin",
  "Details": {
    "ServicePrincipalName": "MSSQLSvc/sqlprod.corp.local:1433",
    "ServiceAccount": "svc_sql_honey",
    "Domain": "CORP.LOCAL"
  }
}
```

---

## Deployment Strategies

### Layered Deception

Deploy multiple Ghost types for comprehensive coverage:

```
Layer 1: Network Reconnaissance
├── Ghost Shares on file servers
├── Ghost SPNs in Active Directory
└── Detects: Initial enumeration

Layer 2: Credential Attacks
├── Ghost Accounts in sensitive OUs
├── Ghost SPNs for Kerberoasting
└── Detects: Credential theft, brute force

Layer 3: Lateral Movement
├── Ghost Files on workstations
├── Ghost Shares on servers
└── Detects: Post-exploitation movement

Layer 4: Data Exfiltration
├── Ghost Files with enticing names
├── Auditing on Ghost resources
└── Detects: Data staging/theft
```

### Placement Recommendations

| Location | Ghost Types | Rationale |
|----------|-------------|-----------|
| Domain Controllers | SPNs, Accounts | Critical AD targets |
| File Servers | Files, Shares | Data exfiltration detection |
| Database Servers | Files, SPNs | High-value targets |
| Workstations | Files | Lateral movement detection |
| Network Shares | Shares, Files | Ransomware detection |

### Naming Strategy

Make Ghosts realistic but trackable:

```
Pattern: <department>_<function>_<identifier>

Examples:
  Account: svc_backup_prod, admin_legacy_01
  File: passwords_backup.txt, db_credentials.xlsx
  Share: Finance_Archive, IT_Scripts
  SPN: MSSQLSvc/sqlbackup.corp.local:1433
```

---

## SIEM Integration

### Splunk

Create a saved search for Ghost alerts:

```spl
index=windows sourcetype=WinEventLog:Security
(
  (EventCode=4624 OR EventCode=4625) TargetUserName="svc_*_honey"
  OR
  (EventCode=4663 OR EventCode=4656) ObjectName="*passwords*" OR ObjectName="*credentials*"
  OR
  (EventCode=5140) ShareName="*Finance*" OR ShareName="*Backup*"
  OR
  (EventCode=4769) ServiceName="*honey*"
)
| eval AlertType=case(
    EventCode IN (4624, 4625), "Ghost Account Access",
    EventCode IN (4663, 4656), "Ghost File Access",
    EventCode=5140, "Ghost Share Access",
    EventCode=4769, "Kerberoasting Detected"
)
| stats count by AlertType, SourceIP, TargetUserName
```

### Microsoft Sentinel

Create an analytics rule:

```kql
let GhostAccounts = dynamic(["svc_backup_honey", "admin_legacy_honey"]);
let GhostSPNs = dynamic(["MSSQLSvc/sqlhoney", "HTTP/webhoney"]);
let GhostShares = dynamic(["Finance_Honey", "Backup_Honey"]);

SecurityEvent
| where TimeGenerated > ago(1h)
| where
    (EventID in (4624, 4625) and TargetAccount has_any (GhostAccounts))
    or (EventID == 4769 and ServiceName has_any (GhostSPNs))
    or (EventID == 5140 and ShareName has_any (GhostShares))
| project TimeGenerated, Computer, EventID, Account, IpAddress
| extend AlertSeverity = "High"
```

### Elastic SIEM

```json
{
  "query": {
    "bool": {
      "should": [
        {
          "bool": {
            "must": [
              { "terms": { "event.code": ["4624", "4625"] } },
              { "wildcard": { "winlog.event_data.TargetUserName": "*honey*" } }
            ]
          }
        },
        {
          "bool": {
            "must": [
              { "term": { "event.code": "4769" } },
              { "wildcard": { "winlog.event_data.ServiceName": "*honey*" } }
            ]
          }
        }
      ]
    }
  }
}
```

---

## Troubleshooting

### Common Issues

#### "Access Denied" During Deployment

```
Cause: Insufficient privileges
Solution: Run GhostChaser as Administrator or provide Domain Admin credentials
```

#### "SPN Already Exists"

```
Cause: Duplicate SPN in the domain
Solution: Use a unique service host name or remove the existing SPN
  setspn -d MSSQLSvc/sqlserver.corp.local:1433 DOMAIN\existing_account
```

#### "Account Already Exists"

```
Cause: Username conflict
Solution: Choose a unique username or remove the existing account
```

#### Events Not Appearing in Logs

```
Cause: Audit policies not configured
Solution: Enable appropriate audit policies (see Detection & Monitoring section)
```

### Verification Commands

```powershell
# Verify Ghost Account exists
Get-ADUser -Identity svc_honey_account

# Verify Ghost SPN is registered
setspn -L svc_honey_account

# Verify Ghost Share exists
Get-SmbShare -Name "Finance_Honey"

# Verify file auditing is enabled
Get-Acl "C:\path\to\ghost\file.txt" | Select-Object -ExpandProperty Audit
```

### Log Locations

| Log Type | Location |
|----------|----------|
| GhostChaser Audit | `C:\ProgramData\GhostChaser\Logs\` |
| Windows Security | Event Viewer > Windows Logs > Security |
| Windows System | Event Viewer > Windows Logs > System |

---

## Best Practices

1. **Document Everything**: Keep a record of all deployed Ghosts
2. **Regular Reviews**: Audit Ghost deployments quarterly
3. **Test Detection**: Periodically trigger Ghosts to verify alerting works
4. **Update Names**: Rotate Ghost names to prevent attacker learning
5. **Layer Defense**: Deploy multiple Ghost types for comprehensive coverage
6. **Alert Tuning**: Ensure Ghost alerts have high priority in your SIEM
7. **Incident Response**: Include Ghost alerts in your IR playbooks

---

## Contributing

Found a bug or have a feature request? Please open an issue on our GitHub repository.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

*GhostChaser - Turning attacker reconnaissance into detection opportunities.*

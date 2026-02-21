![GhostChaser](https://github.com/user-attachments/assets/3a2f3d94-8878-4e04-bddd-53eb0b1a907e)


# 👻 GhostChaser - Cyber Deception Toolkit

**GhostChaser** is a Windows-based cyber deception tool designed to deploy and manage canary accounts, files, network shares, and Service Principal Names (collectively called "Ghosts") across enterprise Windows environments. These Ghosts act as tripwires to detect unauthorized access, lateral movement, Kerberoasting attacks, and malicious activity within your network.

## Overview

GhostChaser enables security teams to implement proactive defense-in-depth strategies using honey tokens and canary resources. When adversaries interact with these Ghosts, their activities can be detected and investigated.

### Key Features

- **Four Ghost Types:**
  - **👤 Account Ghosts**: Canary user accounts (local or domain)
  - **📄 File Ghosts**: Decoy documents with enticing names and content
  - **🗂️ Share Ghosts**: Honeypot network shares with bait files
  - **🎫 SPN Ghosts**: Honey Service Principal Names for Kerberoasting detection

- **Graphical User Interface**: Intuitive WPF-based GUI for easy Ghost management
- **Remote Deployment**: Target local or remote Windows systems on your network
- **Flexible Authentication**: Use current credentials or specify alternate credentials
- **Audit Logging**: Comprehensive logging of all Ghost creation and removal activities
- **File Auditing**: Optional Windows auditing integration for access detection

## Prerequisites

### For Building:
- **Operating System**: Windows 10/11 or Windows Server 2016+
- **.NET 8.0 SDK**: Required for building ([Download](https://dotnet.microsoft.com/download/dotnet/8.0))

### For Running (Self-Contained Build):
- **Operating System**: Windows 10/11 or Windows Server 2016+ (64-bit)
- **Permissions**: Administrator privileges on target systems
- **Domain Environment** (optional): Active Directory for domain Ghost accounts
- **NO .NET Runtime Required** - Everything is included!

### For Running (Framework-Dependent Build):
- **.NET 8.0 Desktop Runtime**: Required ([Download](https://dotnet.microsoft.com/download/dotnet/8.0))
- **Permissions**: Administrator privileges on target systems

## Installation & Building

GhostChaser can be built in two ways: **self-contained** (recommended, no .NET required on target) or **framework-dependent** (requires .NET 8.0 Runtime).

### Option 1: Self-Contained Portable Build (Recommended) ⭐

This creates a **fully portable, single-file executable** with the .NET runtime included. No installation required on target systems!

**Build Command:**
```bash
dotnet publish GhostChaser\GhostChaser.csproj -c Release
```

**Alternative with MSBuild:**
```bash
msbuild GhostChaser\GhostChaser.csproj /p:Configuration=Release /t:Publish
```

**Output Location:**
```
GhostChaser\bin\Release\net8.0-windows\win-x64\publish\GhostChaser.exe
```

**Deployment:**
- The `publish` folder contains everything needed
- Copy the entire `publish` folder to any Windows 10+ machine
- Run `GhostChaser.exe` directly - no dependencies needed!
- Works on machines without .NET installed
- Approximately 70-100MB (includes .NET runtime)

**Key Features:**
✅ Single executable with all dependencies
✅ No .NET installation required on target
✅ Fully portable - USB drive ready
✅ Pre-compiled for faster startup
✅ Perfect for deployment across multiple systems

### Option 2: Framework-Dependent Build

Requires .NET 8.0 Desktop Runtime to be installed on the target machine.

1. **Download** or clone the GhostChaser repository

2. **Build** using one of these methods:

   **Using .NET CLI:**
   ```bash
   dotnet build GhostChaser.sln --configuration Release
   ```

   **Using MSBuild:**
   ```bash
   # Using MSBuild from Visual Studio installation
   "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" GhostChaser.sln /p:Configuration=Release

   # Or if MSBuild is in your PATH
   msbuild GhostChaser.sln /p:Configuration=Release
   ```

   **Using Visual Studio:**
   - Open `GhostChaser.sln` in Visual Studio 2022 or later
   - Set configuration to Release
   - Build → Build Solution (Ctrl+Shift+B)

3. **Install .NET 8.0 Desktop Runtime** on target machine: [Download Here](https://dotnet.microsoft.com/download/dotnet/8.0)

4. **Run** the executable from:
   ```bash
   GhostChaser\bin\Release\net8.0-windows\win-x64\GhostChaser.exe
   ```

   > **Note:** GhostChaser is a C# .NET project and cannot be compiled with cl.exe (C/C++ compiler). Use dotnet CLI or MSBuild instead.

## Portable Deployment Guide

The self-contained build creates a fully portable installation:

### Quick Deployment Steps:

1. **Build once** on your development machine:
   ```bash
   dotnet publish GhostChaser\GhostChaser.csproj -c Release
   ```

2. **Locate the publish folder**:
   ```
   GhostChaser\bin\Release\net8.0-windows\win-x64\publish\
   ```

3. **Deploy anywhere**:
   - Copy the entire `publish` folder to a USB drive
   - Transfer to network share
   - Distribute to multiple workstations
   - Archive for later use

4. **Run on any Windows 10+ machine**:
   - No installation needed
   - No .NET runtime required
   - Just double-click `GhostChaser.exe`
   - Must run as Administrator for Ghost deployment

### What's Included in the Publish Folder:

- `GhostChaser.exe` - Main executable (~70-100MB)
- All .NET runtime components (embedded)
- Required system libraries
- No external dependencies

### Deployment Scenarios:

**Scenario 1: USB Drive Toolkit**
- Copy `publish` folder to USB drive
- Plug into any Windows machine
- Run directly from USB

**Scenario 2: Network Distribution**
- Place `publish` folder on network share
- Users run directly from network
- Or copy locally for performance

**Scenario 3: Multiple Workstation Deployment**
- Build once, deploy everywhere
- No per-machine configuration needed
- Consistent version across all systems

## Usage Guide

### Creating Ghost Accounts

Ghost accounts are canary user accounts designed to detect credential theft and unauthorized access attempts.

**Steps:**
1. Select **Account (User)** as the Ghost type
2. Enter a **Ghost Name** (descriptive identifier)
3. Specify the **Target System** (hostname or IP)
4. Configure **Deployment Credentials**
5. Enter the **Username** for the Ghost account
6. Choose between **Local Account** or **Domain Account**
   - For domain accounts, specify the domain and optional OU
7. Optionally enter a custom **Description** (leave blank for realistic default)
8. Select **Group Memberships** to make the account appear privileged:
   - **Administrators** - Local admin group
   - **Remote Desktop Users** - RDP access group
   - **Backup Operators** - Backup privileges
   - **Domain Admins** (domain accounts only) - High-value target
   - **Enterprise Admins** (domain accounts only) - Highest privilege
9. Click **Deploy Ghost**

**Security Features:**
- **Denied Logon Hours**: Domain accounts are created with zero allowed logon hours, preventing actual authentication even with correct credentials while still generating Event ID 4625 (failed logon)
- **Strong Passwords**: Accounts are created with 32-character cryptographically random passwords
- **Privileged Appearance**: Group memberships make accounts attractive targets for attackers

**Best Practices:**
- Use realistic but slightly suspicious usernames (e.g., `svc_backup`, `admin_temp`, `dbadmin`)
- Add to privileged groups to make accounts more enticing to attackers
- Use domain accounts for enhanced protection (logon hour restrictions)
- Deploy to multiple systems for broader coverage
- Document Ghost accounts to avoid confusion during incident response
- Never use Ghost accounts for legitimate purposes

### Creating Ghost Files

Ghost files are decoy documents designed to detect file system access and data exfiltration attempts.

**Steps:**
1. Select **File (Document)** as the Ghost type
2. Enter a **Ghost Name**
3. Specify the **Target System**
4. Configure **Deployment Credentials**
5. Optionally specify a **File Path** (defaults to shared location)
6. Select a **File Extension** (e.g., `.txt`, `.xlsx`, `.sql`)
7. Enable **File Auditing** if supported
8. Click **Deploy Ghost**

**Best Practices:**
- Use enticing file names (e.g., `passwords.txt`, `credentials.xlsx`, `vpn_config.txt`)
- Place files in common shared directories
- Enable auditing to detect access attempts via Windows Event Logs
- Mix file types to appear legitimate

### Creating Ghost Shares

Ghost shares are honeypot network shares designed to detect lateral movement and unauthorized network access.

**Steps:**
1. Select **Share (Network)** as the Ghost type
2. Enter a **Ghost Name**
3. Specify the **Target System**
4. Configure **Deployment Credentials**
5. Enter a **Share Name** (visible on the network)
6. Optionally specify a **Share Path** (defaults to local directory)
7. Add a **Description** (leave blank for realistic default like "Shared folder for departmental resources")
8. Select **Bait Files** to include in the share:
   - `passwords.txt` - Fake credentials document
   - `credentials.xlsx` - Excel spreadsheet with apparent credentials
   - `database_backup.sql` - SQL backup script with connection strings
   - `vpn.config` - VPN configuration file
   - `id_rsa` - SSH private key file
   - `config.json` - JSON config with database/API credentials
   - `deployment.bat` - Batch script with embedded credentials
   - `admin_access.ps1` - PowerShell admin script
   - `hr_ssn.docx` - HR document with apparent PII
   - `CFO_Budget.pdf` - Executive financial document
9. Enable **Share Auditing** if supported
10. Click **Deploy Ghost**

**Bait File Content:**
Each bait file contains realistic but fake content designed to appear valuable:
- Files are backdated 2-12 months to appear legitimate
- Content includes fake server names, usernames, and redacted passwords
- All sensitive values are marked as `[REDACTED]` or reference contacting IT

**Best Practices:**
- Use realistic share names (e.g., `Backups`, `Finance`, `HR_Documents`)
- Add descriptive text to make shares appear legitimate
- Select bait files that match your organization's environment
- Enable auditing to track access attempts

### Creating Ghost SPNs (Kerberoasting Detection)

Ghost SPNs are honey Service Principal Names designed to detect Kerberoasting attacks - a technique where attackers request TGS tickets for SPNs to crack offline using tools like **Rubeus**, **Kerbrute**, **Impacket GetUserSPNs**, and similar offensive security tools.

**How Kerberoasting Works:**
1. Attacker enumerates SPNs in Active Directory
2. Attacker requests TGS tickets for discovered SPNs
3. TGS tickets are encrypted with the service account's password hash
4. Attacker attempts offline brute-force/dictionary attacks
5. If successful, attacker gains the service account password

**Why Honey SPNs Work:**
- Attackers enumerate **all** SPNs - they cannot distinguish honey SPNs from real ones
- Any TGS request for a honey SPN indicates attack activity
- Detection happens **before** the attacker succeeds in cracking passwords
- High-fidelity alerts with very low false positive rates

**Steps:**
1. Select **SPN (Kerberos)** as the Ghost type
2. Enter a **Ghost Name** (descriptive identifier)
3. Specify the **Target System** (domain controller or domain name)
4. Configure **Deployment Credentials** (requires Domain Admin)
5. Select a **Service Class** from the dropdown or enter a custom one:
   - `MSSQLSvc` - SQL Server (highly targeted by attackers)
   - `HTTP` / `HTTPS` - Web services
   - `LDAP` - LDAP services
   - `CIFS` - Windows file shares
   - `TERMSRV` - Terminal Services/RDP
   - `exchangeMDB` - Exchange Mailbox
   - And 15+ more common service classes
6. Enter the **Service Host** (e.g., `sqlserver.domain.com:1433`)
7. Enter a **Service Account** name (e.g., `svc_sql_backup`)
8. Specify the **Domain**
9. Optionally enter an **Account Description** (leave blank for realistic default)
10. Enable **Create Service Account** if the account doesn't exist
11. Enable **Kerberos Auditing** for Event ID 4769 monitoring
12. Click **Deploy Ghost**

**Security Features:**
- **Denied Logon Hours**: Service accounts are created with zero allowed logon hours, preventing authentication while still triggering Event ID 4769 on TGS requests
- **Strong Passwords**: 32-character cryptographically random passwords that won't crack offline
- **Complete Removal**: When removing a Ghost SPN, both the SPN registration AND the service account are deleted (if created by GhostChaser)

**Command-Line Alternative:**
```cmd
# Create the service account
net user svc_sql_honey P@ssw0rd123! /add /domain

# Register the SPN using setspn
setspn -s MSSQLSvc/sqlserver.corp.local:1433 CORP\svc_sql_honey

# Verify the SPN
setspn -L svc_sql_honey
```

**Best Practices:**
- Use enticing service classes that attackers target (MSSQLSvc, HTTP, LDAP)
- Create realistic-looking service hostnames
- Deploy multiple SPNs across different service types
- Monitor Event ID 4769 (Kerberos Service Ticket Operations) in your SIEM
- Use strong passwords for honey accounts (they should never crack)
- Document all honey SPNs to avoid confusion during incident response

**Detection Events:**
| Event ID | Description | Indicates |
|----------|-------------|-----------|
| 4769 | Kerberos Service Ticket (TGS) requested | Kerberoasting attempt |
| 4770 | Kerberos Service Ticket renewed | Follow-up activity |

**Example SIEM Alert (Splunk):**
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4769
ServiceName IN ("MSSQLSvc/sqlhoney*", "HTTP/webhoney*")
| stats count by ServiceName, TargetUserName, IpAddress
| where count > 0
```

## Remote System Deployment

GhostChaser supports deploying Ghosts to remote Windows systems on the same network.

**Requirements:**
- Network connectivity to target system
- Administrative credentials for the target system
- File and Printer Sharing enabled on target
- Remote Registry service enabled (for shares)
- WMI access enabled on target

**Configuration:**
1. Enter the **hostname** or **IP address** in the Target System field
2. Uncheck **Use Current User Credentials**
3. Enter **Username** with admin rights on the remote system
4. Enter the **Password**
5. Specify the **Domain** if applicable

## Credential Management

GhostChaser handles credentials securely:

- Passwords are stored in memory using `SecureString`
- Credentials are cleared after each operation
- No credentials are logged or persisted to disk
- Always use least-privilege accounts when possible

## Audit Logging

All Ghost operations are logged to:
```
C:\ProgramData\GhostChaser\Logs\GhostChaser_Audit_YYYYMMDD.log
```

**Logged Events:**
- Ghost creation (with full details)
- Ghost removal
- Deployment successes and failures
- Errors and exceptions

**Log Format:** JSON (one event per line)

## Monitoring and Detection

### Windows Event Logs

When auditing is enabled, Ghost access attempts generate events in:
- **Security Log**: Event IDs 4663, 4656 (File/Share access)
- **Security Log**: Event IDs 4624, 4625 (Account logon attempts)
- **Security Log**: Event ID 4769 (Kerberos TGS requests - SPN Ghosts)
- **Security Log**: Event ID 5140 (Network share access)

### Critical Event IDs by Ghost Type

| Ghost Type | Event IDs | Severity | Description |
|------------|-----------|----------|-------------|
| Account | 4624 | **CRITICAL** | Successful logon (investigate immediately) |
| Account | 4625 | HIGH | Failed logon attempt |
| File | 4663, 4656 | HIGH | File access detected |
| Share | 5140 | HIGH | Network share accessed |
| SPN | 4769 | **CRITICAL** | Kerberoasting detected |

### SIEM Integration

Forward Windows Security logs to your SIEM and create alerts for:
- Logon attempts using Ghost account usernames
- File access events for Ghost file paths
- Network share access to Ghost shares
- **TGS requests (Event 4769) for Ghost SPNs** - indicates Kerberoasting

**Example Combined Alert Query (Splunk):**
```spl
index=windows sourcetype=WinEventLog:Security
(
  (EventCode=4624 OR EventCode=4625) TargetUserName="svc_*_honey"
  OR (EventCode=4663) ObjectName="*passwords*"
  OR (EventCode=5140) ShareName="*Backup*"
  OR (EventCode=4769) ServiceName="*honey*"
)
| eval AlertType=case(
    EventCode IN (4624, 4625), "Ghost Account Access",
    EventCode=4663, "Ghost File Access",
    EventCode=5140, "Ghost Share Access",
    EventCode=4769, "Kerberoasting Detected"
)
| stats count by AlertType, src_ip, user
```

### Manual Verification

Use the GhostChaser GUI to track deployed Ghosts and verify their status.

## Security Considerations

### For Defenders

**Best Practices:**
- Deploy Ghosts as part of a layered defense strategy
- Document all Ghost deployments internally
- Integrate Ghost access detection into your incident response procedures
- Regularly review Ghost audit logs
- Remove unused Ghosts to reduce false positives

**Limitations:**
- Sophisticated attackers may identify and avoid Ghosts
- Ghosts require monitoring to be effective
- False positives can occur from legitimate admin activity
- Auditing may generate significant log volume

### Authorized Use Only

**IMPORTANT:** GhostChaser is designed for authorized defensive security operations only.

**Legitimate Use Cases:**
- Enterprise cyber deception programs
- Red team/blue team exercises with proper authorization
- Security research in controlled lab environments
- Penetration testing with written permission
- Educational cybersecurity training

**Prohibited Uses:**
- Deploying Ghosts on systems without authorization
- Creating Ghosts in networks you don't own or manage
- Using the tool for malicious purposes
- Violating organizational policies or laws

**Legal Notice:** Users are responsible for ensuring their use of GhostChaser complies with all applicable laws, regulations, and organizational policies. Always obtain proper authorization before deploying Ghosts.

## Removal and Cleanup

**To Remove a Ghost:**
1. Select the Ghost in the "Deployed Ghosts" list
2. Click the **Remove** button
3. Confirm the removal

**Complete Cleanup:**
- Use the GUI to remove all deployed Ghosts
- Delete Ghost account objects from Active Directory if needed
- Remove Ghost files and directories manually if necessary
- Delete Ghost shares using Computer Management or WMI
- Review audit logs at: `C:\ProgramData\GhostChaser\Logs\`

## Troubleshooting

### "Access Denied" Errors
- Verify you have administrator privileges on the target system
- Check that credentials are correct
- Ensure Windows Firewall allows WMI and SMB traffic
- Confirm Remote Registry service is running

### Ghost Account Creation Fails
- Verify Active Directory permissions for domain accounts
- Check that the username doesn't already exist
- Ensure password complexity requirements are met
- Review audit logs for specific error details

### Ghost Share Creation Fails
- Confirm the share name isn't already in use
- Verify the local path exists or can be created
- Check SMB services are running
- Review WMI permissions on the target system

### Auditing Not Working
- Verify you have permissions to modify audit policies
- Check that object access auditing is enabled via Group Policy
- Confirm Security Event Log is not full
- Review Windows audit policy with `auditpol /get /category:*`

### Ghost SPN Creation Fails
- Verify you have Domain Admin privileges
- Check that the service account name doesn't already exist
- Ensure the SPN isn't already registered to another account (`setspn -Q <SPN>`)
- Verify network connectivity to domain controllers
- If using LDAP method fails, the tool will fallback to `setspn.exe` automatically
- Review audit logs for specific error details

### SPN Already Exists Error
- Check which account has the SPN: `setspn -Q MSSQLSvc/hostname`
- Remove from existing account if needed: `setspn -d MSSQLSvc/hostname DOMAIN\account`
- Use a different service host name for your honey SPN

## Architecture

GhostChaser uses a clean architecture with separation of concerns:

```
GhostChaser/
├── Models/              # Domain models (Ghost types, credentials, status)
│   ├── Ghost.cs         # Base Ghost class and GhostAccount, GhostFile, GhostShare, GhostSPN
│   ├── GhostType.cs     # Enum: Account, File, Share, SPN
│   └── ...
├── Services/            # Business logic (deployment services, logging)
│   ├── GhostAccountService.cs   # Local/Domain account creation
│   ├── GhostFileService.cs      # Bait file creation with templates
│   ├── GhostShareService.cs     # Network share creation via WMI
│   ├── GhostSPNService.cs       # SPN registration (LDAP + setspn.exe)
│   └── AuditLogger.cs           # JSON audit logging
├── ViewModels/          # MVVM view models
├── Views/               # WPF UI views
└── Converters/          # UI data converters
```

**Key Technologies:**
- **WPF**: Modern Windows UI framework
- **C# / .NET 8.0**: Core programming language and framework
- **System.DirectoryServices**: Active Directory integration (SPNs, accounts)
- **System.DirectoryServices.AccountManagement**: User/Group management
- **System.Management**: WMI for remote management
- **MVVM Pattern**: Clean separation of UI and business logic

## Contributing

Contributions are welcome! Please ensure all contributions:
- Follow the existing code style and architecture
- Include appropriate error handling
- Update documentation as needed
- Are intended for defensive security purposes only

## License

This project is provided for educational and authorized defensive security purposes.

## Disclaimer

This tool creates user accounts, files, and network shares on Windows systems. Users are solely responsible for:
- Obtaining proper authorization before use
- Compliance with organizational policies
- Adherence to applicable laws and regulations
- Managing and removing deployed Ghosts
- Monitoring and responding to Ghost triggers

The authors assume no liability for misuse or unauthorized use of this software.

## Support

For issues, questions, or feature requests:
- Review the Troubleshooting section
- Check audit logs for error details
- Verify prerequisites and permissions
- Consult Windows Event Logs for system-level errors

## Version History

**v1.2.0** - Enhanced Security & Customization
- **Logon Hours Denial**: Ghost Accounts and SPN service accounts now have zero allowed logon hours
  - Prevents actual authentication even with correct credentials
  - Still generates Event ID 4625 (failed logon) for accounts and 4769 (TGS) for SPNs
- **Group Membership Options**: Make Ghost Accounts appear privileged
  - Administrators, Remote Desktop Users, Backup Operators
  - Domain Admins, Enterprise Admins (domain accounts only)
- **Bait File Selection**: Choose which bait files to include in Ghost Shares
  - 10 enticing file options (passwords.txt, credentials.xlsx, id_rsa, etc.)
  - Each file has unique, realistic content
  - Files are automatically backdated for authenticity
- **Custom Descriptions**: All Ghost types support custom description fields
  - Avoid telltale "canary" or "honey" text in AD/local users
  - Realistic defaults if left blank
- **Complete SPN Removal**: Removing Ghost SPNs now also deletes the service account (if created by GhostChaser)
- **Fixed**: Ghost Share creation now properly creates network shares via WMI

**v1.1.0** - Kerberoasting Detection
- **NEW: Ghost SPN (Service Principal Name) creation** for detecting Kerberoasting attacks
- Support for 20+ common service classes (MSSQLSvc, HTTP, LDAP, CIFS, etc.)
- Dual deployment methods: LDAP/DirectoryEntry (primary) and setspn.exe (fallback)
- Automatic service account creation option
- Event ID 4769 monitoring integration
- Detection of Rubeus, Kerbrute, Impacket, and similar offensive tools
- Updated UI with SPN configuration panel
- Enhanced audit logging for SPN deployments

**v1.0.0** - Initial Release
- Ghost account creation (local and domain)
- Ghost file creation with multiple templates
- Ghost share creation with bait files
- WPF GUI with MVVM pattern
- Remote system targeting
- Comprehensive audit logging
- Windows auditing integration

---

**Remember:** Ghosts are only effective when properly monitored and integrated into your security operations workflow. Deploy responsibly and maintain situational awareness of all deployed Ghosts.

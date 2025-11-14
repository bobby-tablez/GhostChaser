# GhostChaser Quick Start Guide

## 5-Minute Setup

### 1. Build the Application
```bash
cd GhostChaser
dotnet build GhostChaser.sln --configuration Release
```

### 2. Run GhostChaser
```bash
cd GhostChaser\bin\Release\net8.0-windows
GhostChaser.exe
```

### 3. Deploy Your First Ghost

#### Option A: Local Ghost Account (Easiest)
1. Select **"Account (User)"** radio button
2. Enter Ghost Name: `TestGhost`
3. Target System: Leave as default (current machine)
4. Keep **"Use Current User Credentials"** checked
5. Enter Username: `ghost_testuser`
6. Keep **"Local Account"** selected
7. Click **"Deploy Ghost"**

#### Option B: Ghost File
1. Select **"File (Document)"** radio button
2. Enter Ghost Name: `TestFile`
3. Target System: Leave as default
4. Keep **"Use Current User Credentials"** checked
5. Leave File Path empty (uses default)
6. Select Extension: `.txt`
7. Keep **"Enable File Auditing"** checked
8. Click **"Deploy Ghost"**

#### Option C: Ghost Share
1. Select **"Share (Network)"** radio button
2. Enter Ghost Name: `TestShare`
3. Target System: Leave as default
4. Keep **"Use Current User Credentials"** checked
5. Enter Share Name: `TestGhostShare`
6. Leave Share Path empty (uses default)
7. Enter Description: `Test Ghost Share`
8. Keep **"Enable Share Auditing"** checked
9. Click **"Deploy Ghost"**

### 4. Verify Deployment

**For Ghost Account:**
```bash
net user ghost_testuser
```

**For Ghost File:**
```bash
dir "C:\Users\Public\Documents\Shared\TestFile.txt"
```

**For Ghost Share:**
```bash
net share TestGhostShare
```

### 5. Monitor Ghost Activity

**Check Windows Event Viewer:**
1. Open Event Viewer (`eventvwr.msc`)
2. Navigate to: Windows Logs > Security
3. Filter for Event IDs:
   - 4624, 4625 (Account logon)
   - 4663, 4656 (File/Object access)

**Check GhostChaser Audit Logs:**
```
C:\ProgramData\GhostChaser\Logs\GhostChaser_Audit_YYYYMMDD.log
```

### 6. Remove Ghost (Cleanup)
1. In the GhostChaser GUI, find your Ghost in the "Deployed Ghosts" list
2. Click the **"Remove"** button
3. Confirm removal

## Remote Deployment Example

To deploy a Ghost to a remote system:

1. Enter the remote hostname: `REMOTE-PC-01`
2. Uncheck **"Use Current User Credentials"**
3. Enter Username: `domain\adminuser`
4. Enter Password: `********`
5. Enter Domain: `domain`
6. Configure your Ghost settings
7. Click **"Deploy Ghost"**

## Common Use Cases

### Detecting Credential Theft
Deploy Ghost accounts across multiple workstations. Monitor for logon attempts.

### Detecting Lateral Movement
Deploy Ghost shares on file servers. Monitor for network access.

### Detecting Data Exfiltration
Deploy Ghost files in sensitive directories. Monitor for file reads.

## Tips

- **Start Local**: Test on your own machine first
- **Document Everything**: Keep track of deployed Ghosts
- **Monitor Actively**: Ghosts are only useful if monitored
- **Clean Up**: Remove test Ghosts when done

## Need Help?

See the full [README.md](README.md) for detailed documentation.

## Security Reminder

Only deploy Ghosts on systems you own or have explicit authorization to test!

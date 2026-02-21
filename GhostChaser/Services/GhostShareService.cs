using GhostChaser.Models;
using System;
using System.IO;
using System.Management;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading.Tasks;

namespace GhostChaser.Services
{
    /// <summary>
    /// Service for creating and managing Ghost network shares (canary shares)
    /// </summary>
    public class GhostShareService : IGhostDeploymentService
    {
        public async Task<DeploymentResult> DeployAsync(Ghost ghost, DeploymentCredentials credentials)
        {
            if (ghost is not GhostShare shareGhost)
            {
                return new DeploymentResult
                {
                    Success = false,
                    Message = "Invalid ghost type. Expected GhostShare."
                };
            }

            return await Task.Run(() => CreateGhostShare(shareGhost, credentials));
        }

        public async Task<DeploymentResult> RemoveAsync(Ghost ghost, DeploymentCredentials credentials)
        {
            if (ghost is not GhostShare shareGhost)
            {
                return new DeploymentResult
                {
                    Success = false,
                    Message = "Invalid ghost type. Expected GhostShare."
                };
            }

            return await Task.Run(() => DeleteGhostShare(shareGhost, credentials));
        }

        public async Task<bool> VerifyAsync(Ghost ghost, DeploymentCredentials credentials)
        {
            if (ghost is not GhostShare shareGhost)
                return false;

            return await Task.Run(() => ShareExists(shareGhost, credentials));
        }

        private DeploymentResult CreateGhostShare(GhostShare ghost, DeploymentCredentials credentials)
        {
            try
            {
                string targetSystem = string.IsNullOrEmpty(ghost.TargetSystem) ?
                    Environment.MachineName : ghost.TargetSystem;

                // Create the directory if it doesn't exist
                string sharePath = ghost.SharePath;
                if (string.IsNullOrEmpty(sharePath))
                {
                    sharePath = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.CommonDocuments),
                        "GhostShares",
                        ghost.ShareName
                    );
                }

                if (!Directory.Exists(sharePath))
                {
                    Directory.CreateDirectory(sharePath);
                }

                // Create the network share using WMI FIRST (before adding bait files)
                ManagementScope scope = new ManagementScope($"\\\\{targetSystem}\\root\\cimv2");

                if (!credentials.UseCurrentCredentials && !string.IsNullOrEmpty(credentials.Username))
                {
                    ConnectionOptions options = new ConnectionOptions
                    {
                        Username = credentials.Username,
                        Password = ConvertToUnsecureString(credentials.Password),
                        Authentication = AuthenticationLevel.PacketPrivacy
                    };
                    scope.Options = options;
                }

                scope.Connect();

                // Check if share already exists
                if (ShareExists(ghost.ShareName, scope))
                {
                    return new DeploymentResult
                    {
                        Success = false,
                        Message = $"Share '{ghost.ShareName}' already exists on {targetSystem}"
                    };
                }

                // Create the share
                ManagementClass managementClass = new ManagementClass(scope, new ManagementPath("Win32_Share"), null);
                ManagementBaseObject inParams = managementClass.GetMethodParameters("Create");

                inParams["Path"] = sharePath;
                inParams["Name"] = ghost.ShareName;
                inParams["Type"] = 0; // Disk drive
                inParams["Description"] = ghost.ShareDescription ?? $"Ghost Share - {ghost.Name}";
                inParams["MaximumAllowed"] = null; // No limit

                ManagementBaseObject outParams = managementClass.InvokeMethod("Create", inParams, null);
                uint returnValue = (uint)outParams["ReturnValue"];

                if (returnValue != 0)
                {
                    string errorMessage = GetShareCreationError(returnValue);
                    return new DeploymentResult
                    {
                        Success = false,
                        Message = $"Failed to create share: {errorMessage}",
                        ErrorDetails = $"WMI Return Code: {returnValue}"
                    };
                }

                // Share created successfully - now add selected bait files
                CreateShareBaitFiles(sharePath, ghost.BaitFiles);

                // Enable auditing if requested
                if (ghost.HasAuditingEnabled)
                {
                    EnableShareAuditing(sharePath);
                }

                ghost.SharePath = sharePath;
                ghost.Status = GhostStatus.Active;

                return new DeploymentResult
                {
                    Success = true,
                    Message = $"Ghost share '{ghost.ShareName}' created successfully on {targetSystem} at \\\\{targetSystem}\\{ghost.ShareName}",
                    DeployedGhost = ghost
                };
            }
            catch (Exception ex)
            {
                return new DeploymentResult
                {
                    Success = false,
                    Message = $"Failed to create Ghost share: {ex.Message}",
                    ErrorDetails = ex.ToString()
                };
            }
        }

        private DeploymentResult DeleteGhostShare(GhostShare ghost, DeploymentCredentials credentials)
        {
            try
            {
                string targetSystem = string.IsNullOrEmpty(ghost.TargetSystem) ?
                    Environment.MachineName : ghost.TargetSystem;

                ManagementScope scope = new ManagementScope($"\\\\{targetSystem}\\root\\cimv2");

                if (!credentials.UseCurrentCredentials && !string.IsNullOrEmpty(credentials.Username))
                {
                    ConnectionOptions options = new ConnectionOptions
                    {
                        Username = credentials.Username,
                        Password = ConvertToUnsecureString(credentials.Password),
                        Authentication = AuthenticationLevel.PacketPrivacy
                    };
                    scope.Options = options;
                }

                scope.Connect();

                // Find the share
                ObjectQuery query = new ObjectQuery($"SELECT * FROM Win32_Share WHERE Name = '{ghost.ShareName}'");
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);
                ManagementObjectCollection shares = searcher.Get();

                if (shares.Count == 0)
                {
                    return new DeploymentResult
                    {
                        Success = false,
                        Message = $"Ghost share '{ghost.ShareName}' not found on {targetSystem}"
                    };
                }

                foreach (ManagementObject share in shares)
                {
                    ManagementBaseObject outParams = share.InvokeMethod("Delete", null, null);
                    uint returnValue = (uint)outParams["ReturnValue"];

                    if (returnValue != 0)
                    {
                        return new DeploymentResult
                        {
                            Success = false,
                            Message = $"Failed to delete share. Error code: {returnValue}"
                        };
                    }
                }

                // Only delete the directory if it's safe to do so
                // SAFETY: Only delete if the folder is empty (except for our bait files)
                // or if it was auto-generated by GhostChaser
                if (Directory.Exists(ghost.SharePath) && IsSafeToDeleteShareFolder(ghost.SharePath))
                {
                    try
                    {
                        // First, only delete the bait files we created
                        DeleteBaitFilesOnly(ghost.SharePath);

                        // Only delete the directory if it's now empty
                        if (Directory.GetFileSystemEntries(ghost.SharePath).Length == 0)
                        {
                            Directory.Delete(ghost.SharePath, false); // false = non-recursive
                        }
                    }
                    catch
                    {
                        // Directory deletion is best effort - don't fail the share removal
                    }
                }

                ghost.Status = GhostStatus.Removed;

                return new DeploymentResult
                {
                    Success = true,
                    Message = $"Ghost share '{ghost.ShareName}' removed successfully from {targetSystem}"
                };
            }
            catch (Exception ex)
            {
                return new DeploymentResult
                {
                    Success = false,
                    Message = $"Failed to remove Ghost share: {ex.Message}",
                    ErrorDetails = ex.ToString()
                };
            }
        }

        private bool ShareExists(GhostShare ghost, DeploymentCredentials credentials)
        {
            try
            {
                string targetSystem = string.IsNullOrEmpty(ghost.TargetSystem) ?
                    Environment.MachineName : ghost.TargetSystem;

                ManagementScope scope = new ManagementScope($"\\\\{targetSystem}\\root\\cimv2");
                scope.Connect();

                return ShareExists(ghost.ShareName, scope);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Check if it's safe to delete a share folder.
        /// Prevents deletion of system directories, root drives, and common important paths.
        /// </summary>
        private bool IsSafeToDeleteShareFolder(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return false;

            try
            {
                string fullPath = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                string pathLower = fullPath.ToLowerInvariant();

                // NEVER delete root drives
                if (fullPath.Length <= 3) // e.g., "C:\" or "C:"
                    return false;

                // NEVER delete common system/important directories
                string[] protectedPaths = new[]
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant(),
                    Environment.GetFolderPath(Environment.SpecialFolder.System).ToLowerInvariant(),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).ToLowerInvariant(),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86).ToLowerInvariant(),
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile).ToLowerInvariant(),
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData).ToLowerInvariant(),
                    @"c:\windows",
                    @"c:\program files",
                    @"c:\program files (x86)",
                    @"c:\users",
                    @"c:\programdata"
                };

                foreach (string protectedPath in protectedPaths)
                {
                    if (!string.IsNullOrEmpty(protectedPath))
                    {
                        string normalizedProtected = protectedPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                        // Don't delete if the path IS a protected path or is a parent of one
                        if (pathLower == normalizedProtected || normalizedProtected.StartsWith(pathLower + Path.DirectorySeparatorChar))
                            return false;
                    }
                }

                // Don't delete if path has less than 2 directory levels (e.g., C:\Shares is too shallow)
                string[] pathParts = fullPath.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                if (pathParts.Length < 3) // Drive + at least 2 folders
                    return false;

                return true;
            }
            catch
            {
                return false; // If we can't validate, don't delete
            }
        }

        /// <summary>
        /// Delete only the bait files that GhostChaser created, leaving other files intact.
        /// </summary>
        private void DeleteBaitFilesOnly(string sharePath)
        {
            // All possible bait files that GhostChaser might have created
            string[] baitFileNames = new[]
            {
                "passwords.txt",
                "credentials.xlsx",
                "database_backup.sql",
                "vpn_config.txt",  // Legacy name
                "vpn.config",
                "id_rsa",
                "config.json",
                "deployment.bat",
                "admin_access.ps1",
                "hr_ssn.docx",
                "CFO_Budget.pdf"
            };

            foreach (string fileName in baitFileNames)
            {
                try
                {
                    string filePath = Path.Combine(sharePath, fileName);
                    if (File.Exists(filePath))
                    {
                        File.Delete(filePath);
                    }
                }
                catch
                {
                    // Best effort - continue with other files
                }
            }
        }

        private bool ShareExists(string shareName, ManagementScope scope)
        {
            try
            {
                ObjectQuery query = new ObjectQuery($"SELECT * FROM Win32_Share WHERE Name = '{shareName}'");
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);
                ManagementObjectCollection shares = searcher.Get();
                return shares.Count > 0;
            }
            catch
            {
                return false;
            }
        }

        private void CreateShareBaitFiles(string sharePath, System.Collections.Generic.List<string> selectedFiles)
        {
            if (selectedFiles == null || selectedFiles.Count == 0)
                return;

            try
            {
                foreach (string fileName in selectedFiles)
                {
                    string filePath = Path.Combine(sharePath, fileName);
                    if (!File.Exists(filePath))
                    {
                        string content = GetBaitFileContent(fileName);
                        File.WriteAllText(filePath, content);

                        // Backdate the file
                        DateTime backdateTime = DateTime.Now.AddMonths(-Random.Shared.Next(2, 12));
                        File.SetCreationTime(filePath, backdateTime);
                        File.SetLastWriteTime(filePath, backdateTime.AddDays(Random.Shared.Next(1, 30)));
                    }
                }
            }
            catch
            {
                // Bait file creation is best effort
            }
        }

        private string GetBaitFileContent(string fileName)
        {
            DateTime lastUpdate = DateTime.Now.AddMonths(-Random.Shared.Next(1, 6));

            return fileName.ToLower() switch
            {
                "passwords.txt" => $@"=== SYSTEM CREDENTIALS - INTERNAL USE ONLY ===
Last Updated: {lastUpdate:yyyy-MM-dd}

Domain Admin:
  Username: admin.backup
  Password: [REDACTED - See IT Security]

SQL Server (PROD):
  Server: sql-prod-01.corp.local
  SA Password: [REDACTED]

VPN Gateway:
  Admin: vpnadmin
  Key: [Contact Network Team]

NOTE: Do not share this file. Contact IT Security for access.",

                "credentials.xlsx" => $@"PK...Excel File Header Simulation...
[Binary Excel content - This is a placeholder]
System,Username,Notes
SQL-PROD,sa,Production database
DOMAIN,svc_backup,Backup service account
FIREWALL,admin,Network infrastructure
Last Modified: {lastUpdate:yyyy-MM-dd}",

                "database_backup.sql" => $@"-- Database Backup Script
-- Generated: {lastUpdate:yyyy-MM-dd}
-- Server: sql-prod-01.corp.local
-- WARNING: Contains sensitive schema information

USE master;
GO

-- Backup configuration
BACKUP DATABASE [Production] TO DISK = '\\\\backup-server\\sqlbackups\\prod.bak'
WITH COMPRESSION, STATS = 10;

-- Connection string (for reference):
-- Server=sql-prod-01;Database=Production;User Id=sa;Password=[REDACTED];",

                "vpn.config" => $@"# VPN Configuration File
# Last Modified: {lastUpdate:yyyy-MM-dd}
# DO NOT DISTRIBUTE

[Connection]
Server = vpn.corp.local
Port = 443
Protocol = OpenVPN

[Credentials]
Username = vpn_service
PreSharedKey = [CONTACT NETWORK ADMIN]
Certificate = /etc/vpn/client.crt

[Routes]
CorpNetwork = 10.0.0.0/8
DMZ = 172.16.0.0/12",

                "id_rsa" => $@"-----BEGIN OPENSSH PRIVATE KEY-----
[This file appears to contain an SSH private key]
[Content redacted for security]
Generated: {lastUpdate:yyyy-MM-dd}
Owner: admin@corp.local
Purpose: Production server access
-----END OPENSSH PRIVATE KEY-----",

                "config.json" => $@"{{
  ""application"": ""InternalAPI"",
  ""version"": ""2.1.0"",
  ""lastModified"": ""{lastUpdate:yyyy-MM-dd}"",
  ""database"": {{
    ""host"": ""sql-prod-01.corp.local"",
    ""port"": 1433,
    ""username"": ""api_service"",
    ""password"": ""[REDACTED]""
  }},
  ""apiKeys"": {{
    ""production"": ""[CONTACT DEVOPS]"",
    ""stripe"": ""sk_live_[REDACTED]""
  }},
  ""secrets"": {{
    ""jwtSecret"": ""[REDACTED]"",
    ""encryptionKey"": ""[SEE SECURITY TEAM]""
  }}
}}",

                "deployment.bat" => $@"@echo off
REM Deployment Script - Production
REM Last Modified: {lastUpdate:yyyy-MM-dd}
REM Contact: devops@corp.local

SET SERVER=prod-web-01.corp.local
SET DEPLOY_USER=deploy_svc
SET DEPLOY_PASS=[REDACTED]

echo Connecting to production server...
net use \\%SERVER%\deploy$ /user:%DEPLOY_USER% %DEPLOY_PASS%

echo Deploying application...
xcopy /Y /E ""C:\builds\latest"" ""\\%SERVER%\deploy$\app""

echo Restarting services...
sc \\%SERVER% stop WebApp
sc \\%SERVER% start WebApp",

                "admin_access.ps1" => $@"# Administrative Access Script
# Created: {lastUpdate:yyyy-MM-dd}
# Purpose: Emergency admin access to production systems
# Owner: IT Security Team

$AdminCredential = Get-Credential -Message ""Enter Domain Admin credentials""

# Production Servers
$ProdServers = @(
    ""prod-web-01.corp.local"",
    ""prod-db-01.corp.local"",
    ""prod-app-01.corp.local""
)

# Connect and verify access
foreach ($server in $ProdServers) {{
    Enter-PSSession -ComputerName $server -Credential $AdminCredential
    # Run admin tasks...
}}

# Note: For emergency password, contact IT Security Director",

                "hr_ssn.docx" => $@"[Microsoft Word Document Header]
HUMAN RESOURCES - CONFIDENTIAL
Employee Records Export
Generated: {lastUpdate:yyyy-MM-dd}

This document contains sensitive PII including:
- Employee Social Security Numbers
- Salary Information
- Personal Contact Details

ACCESS RESTRICTED TO HR MANAGEMENT ONLY
For access requests, contact HR Director.

[Document content redacted]",

                "CFO_Budget.pdf" => $@"%PDF-1.4
[PDF Header Simulation]

CONFIDENTIAL - EXECUTIVE USE ONLY

FY2024 Budget Planning Document
Prepared for: CFO Office
Date: {lastUpdate:yyyy-MM-dd}

Contents:
- Q1-Q4 Revenue Projections
- Capital Expenditure Plans
- M&A Target Analysis
- Executive Compensation Review

Distribution: C-Suite Only
Do not forward or copy.

[Content continues...]
%%EOF",

                _ => $@"CONFIDENTIAL - {fileName}
========================

This file contains sensitive information.
Access restricted to authorized personnel only.

Last Updated: {lastUpdate:yyyy-MM-dd}
Classification: CONFIDENTIAL"
            };
        }

        private void EnableShareAuditing(string sharePath)
        {
            try
            {
                DirectoryInfo dirInfo = new DirectoryInfo(sharePath);
                DirectorySecurity dirSecurity = dirInfo.GetAccessControl();

                // Add audit rule for successful access
                FileSystemAuditRule auditRule = new FileSystemAuditRule(
                    new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                    FileSystemRights.Read | FileSystemRights.ListDirectory | FileSystemRights.ReadData,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AuditFlags.Success
                );

                dirSecurity.AddAuditRule(auditRule);
                dirInfo.SetAccessControl(dirSecurity);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Could not enable auditing on {sharePath}: {ex.Message}");
            }
        }

        private string GetShareCreationError(uint errorCode)
        {
            return errorCode switch
            {
                0 => "Success",
                2 => "Access denied",
                8 => "Unknown failure",
                9 => "Invalid name",
                10 => "Invalid level",
                21 => "Invalid parameter",
                22 => "Duplicate share",
                23 => "Redirected path",
                24 => "Unknown device or directory",
                25 => "Net name not found",
                _ => $"Unknown error (code: {errorCode})"
            };
        }

        private string? ConvertToUnsecureString(System.Security.SecureString? secureString)
        {
            if (secureString == null)
                return null;

            IntPtr valuePtr = IntPtr.Zero;
            try
            {
                valuePtr = System.Runtime.InteropServices.Marshal.SecureStringToGlobalAllocUnicode(secureString);
                return System.Runtime.InteropServices.Marshal.PtrToStringUni(valuePtr);
            }
            finally
            {
                System.Runtime.InteropServices.Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
            }
        }
    }
}

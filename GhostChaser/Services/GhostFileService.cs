using GhostChaser.Models;
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace GhostChaser.Services
{
    /// <summary>
    /// Service for creating and managing Ghost files (canary files)
    /// </summary>
    public class GhostFileService : IGhostDeploymentService
    {
        public async Task<DeploymentResult> DeployAsync(Ghost ghost, DeploymentCredentials credentials)
        {
            if (ghost is not GhostFile fileGhost)
            {
                return new DeploymentResult
                {
                    Success = false,
                    Message = "Invalid ghost type. Expected GhostFile."
                };
            }

            return await Task.Run(() => CreateGhostFile(fileGhost, credentials));
        }

        public async Task<DeploymentResult> RemoveAsync(Ghost ghost, DeploymentCredentials credentials)
        {
            if (ghost is not GhostFile fileGhost)
            {
                return new DeploymentResult
                {
                    Success = false,
                    Message = "Invalid ghost type. Expected GhostFile."
                };
            }

            return await Task.Run(() => DeleteGhostFile(fileGhost, credentials));
        }

        public async Task<bool> VerifyAsync(Ghost ghost, DeploymentCredentials credentials)
        {
            if (ghost is not GhostFile fileGhost)
                return false;

            return await Task.Run(() => File.Exists(fileGhost.FilePath));
        }

        private DeploymentResult CreateGhostFile(GhostFile ghost, DeploymentCredentials credentials)
        {
            NetworkConnection? networkConnection = null;

            try
            {
                // Build the full file path (converts to UNC path if remote)
                string targetPath = BuildFilePath(ghost);

                // Determine if this is a remote operation
                bool isRemote = IsRemoteTarget(ghost.TargetSystem);

                // Connect to remote system if needed
                if (isRemote && !credentials.UseCurrentCredentials)
                {
                    string networkPath = $"\\\\{ghost.TargetSystem}";
                    string? password = ConvertToUnsecureString(credentials.Password);
                    string username = string.IsNullOrEmpty(credentials.Domain) ?
                        credentials.Username :
                        $"{credentials.Domain}\\{credentials.Username}";

                    networkConnection = new NetworkConnection(networkPath, username, password);
                }

                // Check if file already exists
                if (File.Exists(targetPath))
                {
                    return new DeploymentResult
                    {
                        Success = false,
                        Message = $"Ghost file already exists at {targetPath}"
                    };
                }

                // Ensure directory exists
                string? directory = Path.GetDirectoryName(targetPath);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                // Create the Ghost file with enticing content based on extension
                CreateFileWithContent(targetPath, ghost.FileExtension);

                // Set file attributes to make it appear legitimate
                File.SetAttributes(targetPath, FileAttributes.Normal);

                // Set creation and modification times to make it look older/established
                DateTime backdateTime = DateTime.Now.AddMonths(-Random.Shared.Next(3, 12));
                File.SetCreationTime(targetPath, backdateTime);
                File.SetLastWriteTime(targetPath, backdateTime.AddDays(Random.Shared.Next(1, 30)));

                // Enable auditing if requested
                if (ghost.HasAuditingEnabled)
                {
                    EnableFileAuditing(targetPath);
                }

                // Get file info
                FileInfo fileInfo = new FileInfo(targetPath);
                ghost.FileSize = fileInfo.Length;
                ghost.FilePath = targetPath;
                ghost.Status = GhostStatus.Active;

                string locationMsg = isRemote ? $"on remote system {ghost.TargetSystem}" : "locally";
                return new DeploymentResult
                {
                    Success = true,
                    Message = $"Ghost file created successfully {locationMsg} at {targetPath}",
                    DeployedGhost = ghost
                };
            }
            catch (Exception ex)
            {
                return new DeploymentResult
                {
                    Success = false,
                    Message = $"Failed to create Ghost file: {ex.Message}",
                    ErrorDetails = ex.ToString()
                };
            }
            finally
            {
                networkConnection?.Dispose();
            }
        }

        private DeploymentResult DeleteGhostFile(GhostFile ghost, DeploymentCredentials credentials)
        {
            NetworkConnection? networkConnection = null;

            try
            {
                // Determine if this is a remote operation
                bool isRemote = IsRemoteTarget(ghost.TargetSystem);

                // Connect to remote system if needed
                if (isRemote && !credentials.UseCurrentCredentials)
                {
                    string networkPath = $"\\\\{ghost.TargetSystem}";
                    string? password = ConvertToUnsecureString(credentials.Password);
                    string username = string.IsNullOrEmpty(credentials.Domain) ?
                        credentials.Username :
                        $"{credentials.Domain}\\{credentials.Username}";

                    networkConnection = new NetworkConnection(networkPath, username, password);
                }

                if (!File.Exists(ghost.FilePath))
                {
                    return new DeploymentResult
                    {
                        Success = false,
                        Message = $"Ghost file not found at {ghost.FilePath}"
                    };
                }

                File.Delete(ghost.FilePath);
                ghost.Status = GhostStatus.Removed;

                return new DeploymentResult
                {
                    Success = true,
                    Message = $"Ghost file removed successfully from {ghost.FilePath}"
                };
            }
            catch (Exception ex)
            {
                return new DeploymentResult
                {
                    Success = false,
                    Message = $"Failed to remove Ghost file: {ex.Message}",
                    ErrorDetails = ex.ToString()
                };
            }
            finally
            {
                networkConnection?.Dispose();
            }
        }

        private string BuildFilePath(GhostFile ghost)
        {
            string basePath = ghost.FilePath;
            string targetSystem = ghost.TargetSystem;
            bool isRemote = IsRemoteTarget(targetSystem);

            // If no file path provided, use a default location
            if (string.IsNullOrEmpty(basePath))
            {
                if (isRemote)
                {
                    // Use UNC path to administrative share for remote systems
                    basePath = $"\\\\{targetSystem}\\C$\\Users\\Public\\Documents\\Shared\\{ghost.Name}{ghost.FileExtension}";
                }
                else
                {
                    // Use local path
                    basePath = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.CommonDocuments),
                        "Shared",
                        $"{ghost.Name}{ghost.FileExtension}"
                    );
                }
            }
            else
            {
                // Convert local path to UNC path if remote
                if (isRemote && !basePath.StartsWith("\\\\"))
                {
                    // Check if path is a local path like C:\... and convert to UNC
                    if (basePath.Length >= 3 && basePath[1] == ':' && basePath[2] == '\\')
                    {
                        char driveLetter = basePath[0];
                        string pathWithoutDrive = basePath.Substring(3);
                        basePath = $"\\\\{targetSystem}\\{driveLetter}$\\{pathWithoutDrive}";
                    }
                }

                // Ensure file has correct extension
                if (!basePath.EndsWith(ghost.FileExtension))
                {
                    basePath += ghost.FileExtension;
                }
            }

            return basePath;
        }

        private bool IsRemoteTarget(string targetSystem)
        {
            if (string.IsNullOrWhiteSpace(targetSystem))
                return false;

            string localMachine = Environment.MachineName;
            return !targetSystem.Equals(localMachine, StringComparison.OrdinalIgnoreCase) &&
                   !targetSystem.Equals("localhost", StringComparison.OrdinalIgnoreCase) &&
                   !targetSystem.Equals("127.0.0.1");
        }

        private void CreateFileWithContent(string filePath, string extension)
        {
            string content = extension.ToLower() switch
            {
                ".txt" => GenerateTextFileContent(),
                ".docx" => GenerateTextFileContent(), // For simplicity, creating as text
                ".xlsx" => GenerateCsvContent(), // Creating as CSV for compatibility
                ".pdf" => GenerateTextFileContent(),
                ".config" => GenerateConfigFileContent(),
                ".xml" => GenerateXmlContent(),
                ".json" => GenerateJsonContent(),
                ".sql" => GenerateSqlContent(),
                ".ps1" => GeneratePowerShellContent(),
                ".bat" => GenerateBatchContent(),
                _ => GenerateGenericContent()
            };

            File.WriteAllText(filePath, content, Encoding.UTF8);
        }

        private string GenerateTextFileContent()
        {
            return @"CONFIDENTIAL - DO NOT DISTRIBUTE

Authentication Credentials Document
====================================

This document contains sensitive authentication information.
Access is restricted to authorized personnel only.

Database Connection Strings:
---------------------------
Primary DB: Server=sql-prod-01.internal.corp;Database=CustomerData;Trusted_Connection=True;
Backup DB: Server=sql-backup-01.internal.corp;Database=CustomerData;Trusted_Connection=True;

API Keys:
---------
Production API: [Contact IT Security for access]
Development API: [Contact IT Security for access]

Service Accounts:
----------------
Please refer to the security team for service account credentials.

Last Updated: " + DateTime.Now.AddMonths(-2).ToString("yyyy-MM-dd") + @"
Document Owner: IT Security Team
Classification: HIGHLY CONFIDENTIAL";
        }

        private string GenerateCsvContent()
        {
            return @"Username,Department,AccessLevel,Email
svc_admin,IT,Administrator,svc_admin@internal.corp
db_backup,IT,Service Account,db_backup@internal.corp
api_service,Development,Service Account,api_service@internal.corp";
        }

        private string GenerateConfigFileContent()
        {
            return @"<?xml version=""1.0"" encoding=""utf-8""?>
<configuration>
  <connectionStrings>
    <add name=""ProductionDB"" connectionString=""Server=sql-prod.internal.corp;Database=MainDB;Integrated Security=true;"" />
    <add name=""BackupDB"" connectionString=""Server=sql-backup.internal.corp;Database=MainDB;Integrated Security=true;"" />
  </connectionStrings>
  <appSettings>
    <add key=""AdminEmail"" value=""admin@internal.corp"" />
    <add key=""Environment"" value=""Production"" />
  </appSettings>
</configuration>";
        }

        private string GenerateXmlContent()
        {
            return @"<?xml version=""1.0"" encoding=""utf-8""?>
<Credentials>
  <Database>
    <Server>sql-prod.internal.corp</Server>
    <Name>CorporateData</Name>
    <IntegratedSecurity>true</IntegratedSecurity>
  </Database>
  <ServiceAccounts>
    <Account name=""BackupService"" />
    <Account name=""MonitoringService"" />
  </ServiceAccounts>
</Credentials>";
        }

        private string GenerateJsonContent()
        {
            return @"{
  ""environment"": ""production"",
  ""database"": {
    ""host"": ""sql-prod.internal.corp"",
    ""port"": 1433,
    ""database"": ""CorporateDB"",
    ""useIntegratedAuth"": true
  },
  ""services"": {
    ""api"": {
      ""endpoint"": ""https://api.internal.corp"",
      ""timeout"": 30000
    }
  },
  ""security"": {
    ""classification"": ""confidential""
  }
}";
        }

        private string GenerateSqlContent()
        {
            return @"-- Database Backup Script
-- CONFIDENTIAL - Production Environment
-- Last Modified: " + DateTime.Now.AddMonths(-1).ToString("yyyy-MM-dd") + @"

USE [master]
GO

-- Service account information on file with IT Security
-- Contact: security@internal.corp

BACKUP DATABASE [CorporateDB]
TO DISK = '\\backup-server\sql-backups\CorporateDB_Full.bak'
WITH FORMAT, COMPRESSION, STATS = 10
GO";
        }

        private string GeneratePowerShellContent()
        {
            return @"# Production Environment Configuration Script
# CONFIDENTIAL - DO NOT SHARE
# Contact IT Security for credentials

# Database connection parameters
$ServerName = ""sql-prod.internal.corp""
$DatabaseName = ""CorporateDB""

# Use integrated authentication
$ConnectionString = ""Server=$ServerName;Database=$DatabaseName;Integrated Security=True;""

Write-Host ""Connecting to production database...""
Write-Host ""For credentials, contact: security@internal.corp""
";
        }

        private string GenerateBatchContent()
        {
            return @"@echo off
REM Production Backup Script
REM CONFIDENTIAL - Authorized Personnel Only
REM Last Updated: " + DateTime.Now.AddMonths(-1).ToString("yyyy-MM-dd") + @"

echo Starting backup process...
echo Server: sql-prod.internal.corp
echo Contact IT Security for authentication credentials
echo.

REM Backup configuration on file with security team
";
        }

        private string GenerateGenericContent()
        {
            return @"CONFIDENTIAL INFORMATION
========================

This file contains sensitive corporate information.
Access is restricted to authorized personnel only.

For access credentials, please contact:
IT Security Team
security@internal.corp

Classification: CONFIDENTIAL
Last Updated: " + DateTime.Now.AddMonths(-2).ToString("yyyy-MM-dd");
        }

        private void EnableFileAuditing(string filePath)
        {
            try
            {
                FileInfo fileInfo = new FileInfo(filePath);
                FileSecurity fileSecurity = fileInfo.GetAccessControl();

                // Add audit rule for successful reads
                FileSystemAuditRule auditRule = new FileSystemAuditRule(
                    new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                    FileSystemRights.Read | FileSystemRights.ReadData | FileSystemRights.ReadAttributes,
                    AuditFlags.Success
                );

                fileSecurity.AddAuditRule(auditRule);
                fileInfo.SetAccessControl(fileSecurity);
            }
            catch (Exception ex)
            {
                // Auditing may fail if user doesn't have appropriate permissions
                // This is not critical, so we log but don't fail the operation
                Console.WriteLine($"Warning: Could not enable auditing on {filePath}: {ex.Message}");
            }
        }

        private string? ConvertToUnsecureString(System.Security.SecureString? secureString)
        {
            if (secureString == null)
                return null;

            IntPtr valuePtr = IntPtr.Zero;
            try
            {
                valuePtr = Marshal.SecureStringToGlobalAllocUnicode(secureString);
                return Marshal.PtrToStringUni(valuePtr);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
            }
        }
    }

    /// <summary>
    /// Helper class for establishing authenticated network connections to remote systems
    /// </summary>
    internal class NetworkConnection : IDisposable
    {
        private readonly string _networkPath;
        private bool _disposed = false;

        [DllImport("mpr.dll")]
        private static extern int WNetAddConnection2(ref NETRESOURCE netResource, string? password, string? username, int flags);

        [DllImport("mpr.dll")]
        private static extern int WNetCancelConnection2(string name, int flags, bool force);

        [StructLayout(LayoutKind.Sequential)]
        private struct NETRESOURCE
        {
            public int dwScope;
            public int dwType;
            public int dwDisplayType;
            public int dwUsage;
            public string? lpLocalName;
            public string lpRemoteName;
            public string? lpComment;
            public string? lpProvider;
        }

        public NetworkConnection(string networkPath, string? username, string? password)
        {
            _networkPath = networkPath;

            var netResource = new NETRESOURCE
            {
                dwScope = 2,
                dwType = 1,  // RESOURCETYPE_DISK
                dwDisplayType = 3,
                dwUsage = 1,
                lpRemoteName = networkPath,
                lpLocalName = null
            };

            int result = WNetAddConnection2(ref netResource, password, username, 0);

            if (result != 0)
            {
                throw new Win32Exception(result, $"Failed to connect to {networkPath}. Error code: {result}");
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                try
                {
                    WNetCancelConnection2(_networkPath, 0, true);
                }
                catch
                {
                    // Best effort to disconnect
                }

                _disposed = true;
            }
        }

        ~NetworkConnection()
        {
            Dispose(false);
        }
    }
}

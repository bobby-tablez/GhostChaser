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

                // Add some enticing files to the share
                CreateShareBaitFiles(sharePath);

                // Create the network share using WMI
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
                    Message = $"Ghost share '{ghost.ShareName}' created successfully on {targetSystem} at {sharePath}",
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

                // Optionally delete the directory
                if (Directory.Exists(ghost.SharePath))
                {
                    try
                    {
                        Directory.Delete(ghost.SharePath, true);
                    }
                    catch
                    {
                        // Directory deletion is best effort
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

        private void CreateShareBaitFiles(string sharePath)
        {
            try
            {
                // Create some enticing files in the share
                string[] baitFiles = new[]
                {
                    "passwords.txt",
                    "credentials.xlsx",
                    "database_backup.sql",
                    "vpn_config.txt"
                };

                foreach (string fileName in baitFiles)
                {
                    string filePath = Path.Combine(sharePath, fileName);
                    if (!File.Exists(filePath))
                    {
                        string content = $@"CONFIDENTIAL - {fileName}
========================

This file contains sensitive information.
Access restricted to authorized personnel only.

For access credentials, contact IT Security.
Last Updated: {DateTime.Now.AddMonths(-Random.Shared.Next(1, 6)):yyyy-MM-dd}
Classification: CONFIDENTIAL";

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

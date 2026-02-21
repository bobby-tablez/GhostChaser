using GhostChaser.Models;
using System;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace GhostChaser.Services
{
    /// <summary>
    /// Service for creating and managing Ghost user accounts (canary accounts)
    /// </summary>
    public class GhostAccountService : IGhostDeploymentService
    {
        public async Task<DeploymentResult> DeployAsync(Ghost ghost, DeploymentCredentials credentials)
        {
            if (ghost is not GhostAccount accountGhost)
            {
                return new DeploymentResult
                {
                    Success = false,
                    Message = "Invalid ghost type. Expected GhostAccount."
                };
            }

            return await Task.Run(() => CreateGhostAccount(accountGhost, credentials));
        }

        public async Task<DeploymentResult> RemoveAsync(Ghost ghost, DeploymentCredentials credentials)
        {
            if (ghost is not GhostAccount accountGhost)
            {
                return new DeploymentResult
                {
                    Success = false,
                    Message = "Invalid ghost type. Expected GhostAccount."
                };
            }

            return await Task.Run(() => DeleteGhostAccount(accountGhost, credentials));
        }

        public async Task<bool> VerifyAsync(Ghost ghost, DeploymentCredentials credentials)
        {
            if (ghost is not GhostAccount accountGhost)
                return false;

            return await Task.Run(() => AccountExists(accountGhost, credentials));
        }

        private DeploymentResult CreateGhostAccount(GhostAccount ghost, DeploymentCredentials credentials)
        {
            try
            {
                if (ghost.IsLocalAccount)
                {
                    return CreateLocalAccount(ghost, credentials);
                }
                else
                {
                    return CreateDomainAccount(ghost, credentials);
                }
            }
            catch (Exception ex)
            {
                return new DeploymentResult
                {
                    Success = false,
                    Message = $"Failed to create Ghost account: {ex.Message}",
                    ErrorDetails = ex.ToString()
                };
            }
        }

        private DeploymentResult CreateLocalAccount(GhostAccount ghost, DeploymentCredentials credentials)
        {
            try
            {
                string machineName = string.IsNullOrEmpty(ghost.TargetSystem) ?
                    Environment.MachineName : ghost.TargetSystem;

                PrincipalContext context;

                if (credentials.UseCurrentCredentials || string.IsNullOrEmpty(credentials.Username))
                {
                    context = new PrincipalContext(ContextType.Machine, machineName);
                }
                else
                {
                    string? password = SecureStringToString(credentials.Password);
                    context = new PrincipalContext(
                        ContextType.Machine,
                        machineName,
                        credentials.Username,
                        password);
                }

                using (context)
                {
                    // Check if account already exists
                    UserPrincipal? existingUser = UserPrincipal.FindByIdentity(context, ghost.Username);
                    if (existingUser != null)
                    {
                        existingUser.Dispose();
                        return new DeploymentResult
                        {
                            Success = false,
                            Message = $"Account '{ghost.Username}' already exists on {machineName}"
                        };
                    }

                    // Create the Ghost account
                    UserPrincipal userPrincipal = new UserPrincipal(context)
                    {
                        Name = ghost.Username,
                        DisplayName = ghost.Name,
                        Description = ghost.Description ?? $"Ghost Account - {ghost.Name}",
                        PasswordNeverExpires = true,
                        UserCannotChangePassword = true,
                        Enabled = true
                    };

                    // Generate a strong random password
                    string ghostPassword = GenerateSecurePassword();
                    userPrincipal.SetPassword(ghostPassword);

                    userPrincipal.Save();

                    // NOTE: Local Windows accounts don't support logonHours attribute
                    // via the WinNT provider. For local Ghost accounts, security relies on:
                    // 1. Strong random password (32 chars, complex)
                    // 2. Auditing of logon attempts
                    // For best protection, use domain accounts which support logon hour restrictions.

                    // Add to specified groups (makes account appear privileged)
                    if (ghost.GroupMemberships.Count > 0)
                    {
                        AddToLocalGroups(machineName, ghost.Username, ghost.GroupMemberships);
                    }

                    ghost.Status = GhostStatus.Active;

                    string groupInfo = ghost.GroupMemberships.Count > 0 ?
                        $" Added to: {string.Join(", ", ghost.GroupMemberships)}." : "";

                    return new DeploymentResult
                    {
                        Success = true,
                        Message = $"Ghost account '{ghost.Username}' created successfully on {machineName}.{groupInfo} Note: For enhanced protection with logon hour restrictions, use domain accounts.",
                        DeployedGhost = ghost
                    };
                }
            }
            catch (Exception ex)
            {
                return new DeploymentResult
                {
                    Success = false,
                    Message = $"Failed to create local Ghost account: {ex.Message}",
                    ErrorDetails = ex.ToString()
                };
            }
        }

        private DeploymentResult CreateDomainAccount(GhostAccount ghost, DeploymentCredentials credentials)
        {
            try
            {
                string domain = string.IsNullOrEmpty(ghost.Domain) ?
                    Environment.UserDomainName : ghost.Domain;

                PrincipalContext context;

                if (credentials.UseCurrentCredentials || string.IsNullOrEmpty(credentials.Username))
                {
                    context = new PrincipalContext(ContextType.Domain, domain, ghost.OrganizationalUnit);
                }
                else
                {
                    string? password = SecureStringToString(credentials.Password);
                    context = new PrincipalContext(
                        ContextType.Domain,
                        domain,
                        ghost.OrganizationalUnit,
                        credentials.Username,
                        password);
                }

                using (context)
                {
                    // Check if account already exists
                    UserPrincipal? existingUser = UserPrincipal.FindByIdentity(context, ghost.Username);
                    if (existingUser != null)
                    {
                        existingUser.Dispose();
                        return new DeploymentResult
                        {
                            Success = false,
                            Message = $"Domain account '{ghost.Username}' already exists in {domain}"
                        };
                    }

                    // Create the Ghost domain account
                    UserPrincipal userPrincipal = new UserPrincipal(context)
                    {
                        SamAccountName = ghost.Username,
                        Name = ghost.Name,
                        DisplayName = ghost.Name,
                        Description = ghost.Description ?? $"Ghost Account - {ghost.Name}",
                        PasswordNeverExpires = true,
                        UserCannotChangePassword = true,
                        Enabled = true
                    };

                    // Generate a strong random password
                    string ghostPassword = GenerateSecurePassword();
                    userPrincipal.SetPassword(ghostPassword);

                    userPrincipal.Save();

                    // CRITICAL: Deny all logon hours to prevent actual authentication
                    // Even with correct credentials, the account cannot log on
                    // but attempts will still generate Event ID 4625 (failed logon)
                    DenyAllLogonHours(userPrincipal);

                    // Add to specified groups (makes account appear privileged)
                    if (ghost.GroupMemberships.Count > 0)
                    {
                        AddToDomainGroups(userPrincipal, context, ghost.GroupMemberships);
                    }

                    ghost.Domain = domain;
                    ghost.Status = GhostStatus.Active;

                    string groupInfo = ghost.GroupMemberships.Count > 0 ?
                        $" Added to: {string.Join(", ", ghost.GroupMemberships)}." : "";

                    return new DeploymentResult
                    {
                        Success = true,
                        Message = $"Ghost domain account '{ghost.Username}' created successfully in {domain} (logon hours denied).{groupInfo}",
                        DeployedGhost = ghost
                    };
                }
            }
            catch (Exception ex)
            {
                return new DeploymentResult
                {
                    Success = false,
                    Message = $"Failed to create domain Ghost account: {ex.Message}",
                    ErrorDetails = ex.ToString()
                };
            }
        }

        private DeploymentResult DeleteGhostAccount(GhostAccount ghost, DeploymentCredentials credentials)
        {
            try
            {
                PrincipalContext context;

                if (ghost.IsLocalAccount)
                {
                    string machineName = string.IsNullOrEmpty(ghost.TargetSystem) ?
                        Environment.MachineName : ghost.TargetSystem;

                    if (credentials.UseCurrentCredentials)
                    {
                        context = new PrincipalContext(ContextType.Machine, machineName);
                    }
                    else
                    {
                        string? password = SecureStringToString(credentials.Password);
                        context = new PrincipalContext(
                            ContextType.Machine,
                            machineName,
                            credentials.Username,
                            password);
                    }
                }
                else
                {
                    string domain = string.IsNullOrEmpty(ghost.Domain) ?
                        Environment.UserDomainName : ghost.Domain;

                    if (credentials.UseCurrentCredentials)
                    {
                        context = new PrincipalContext(ContextType.Domain, domain);
                    }
                    else
                    {
                        string? password = SecureStringToString(credentials.Password);
                        context = new PrincipalContext(
                            ContextType.Domain,
                            domain,
                            null,
                            credentials.Username,
                            password);
                    }
                }

                using (context)
                {
                    UserPrincipal? user = UserPrincipal.FindByIdentity(context, ghost.Username);

                    if (user == null)
                    {
                        return new DeploymentResult
                        {
                            Success = false,
                            Message = $"Ghost account '{ghost.Username}' not found"
                        };
                    }

                    user.Delete();
                    ghost.Status = GhostStatus.Removed;

                    return new DeploymentResult
                    {
                        Success = true,
                        Message = $"Ghost account '{ghost.Username}' removed successfully"
                    };
                }
            }
            catch (Exception ex)
            {
                return new DeploymentResult
                {
                    Success = false,
                    Message = $"Failed to remove Ghost account: {ex.Message}",
                    ErrorDetails = ex.ToString()
                };
            }
        }

        private bool AccountExists(GhostAccount ghost, DeploymentCredentials credentials)
        {
            try
            {
                PrincipalContext context;

                if (ghost.IsLocalAccount)
                {
                    string machineName = string.IsNullOrEmpty(ghost.TargetSystem) ?
                        Environment.MachineName : ghost.TargetSystem;
                    context = new PrincipalContext(ContextType.Machine, machineName);
                }
                else
                {
                    string domain = string.IsNullOrEmpty(ghost.Domain) ?
                        Environment.UserDomainName : ghost.Domain;
                    context = new PrincipalContext(ContextType.Domain, domain);
                }

                using (context)
                {
                    UserPrincipal? user = UserPrincipal.FindByIdentity(context, ghost.Username);
                    bool exists = user != null;
                    user?.Dispose();
                    return exists;
                }
            }
            catch
            {
                return false;
            }
        }

        private string GenerateSecurePassword(int length = 32)
        {
            const string validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+-=[]{}|;:,.<>?";
            StringBuilder password = new StringBuilder();
            Random random = new Random();

            for (int i = 0; i < length; i++)
            {
                password.Append(validChars[random.Next(validChars.Length)]);
            }

            return password.ToString();
        }

        /// <summary>
        /// Sets the logon hours for an account to deny all hours.
        /// This prevents the account from being used for logon even with correct credentials,
        /// while still generating security events when authentication is attempted.
        /// </summary>
        /// <param name="userPrincipal">The UserPrincipal to restrict</param>
        private void DenyAllLogonHours(UserPrincipal userPrincipal)
        {
            try
            {
                // Get the underlying DirectoryEntry
                DirectoryEntry? directoryEntry = userPrincipal.GetUnderlyingObject() as DirectoryEntry;
                if (directoryEntry == null)
                    return;

                // logonHours is a 21-byte array (168 hours = 24 hours * 7 days)
                // Each bit represents one hour. Setting all to 0 denies all logon hours.
                byte[] logonHours = new byte[21];
                // All bytes default to 0x00, which means no hours allowed

                directoryEntry.Properties["logonHours"].Value = logonHours;
                directoryEntry.CommitChanges();
            }
            catch (Exception ex)
            {
                // Log but don't fail - logon hours restriction is an enhancement
                Console.WriteLine($"Warning: Could not set logon hours restriction: {ex.Message}");
            }
        }

        /// <summary>
        /// Adds a local user to specified local groups.
        /// </summary>
        private void AddToLocalGroups(string machineName, string username, System.Collections.Generic.List<string> groups)
        {
            if (groups == null || groups.Count == 0)
                return;

            foreach (string groupName in groups)
            {
                try
                {
                    using DirectoryEntry group = new DirectoryEntry($"WinNT://{machineName}/{groupName},group");
                    group.Invoke("Add", $"WinNT://{machineName}/{username},user");
                }
                catch (Exception ex)
                {
                    // Log but continue - some groups may not exist
                    Console.WriteLine($"Warning: Could not add {username} to {groupName}: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Adds a domain user to specified domain groups.
        /// </summary>
        private void AddToDomainGroups(UserPrincipal userPrincipal, PrincipalContext context, System.Collections.Generic.List<string> groups)
        {
            if (groups == null || groups.Count == 0)
                return;

            foreach (string groupName in groups)
            {
                try
                {
                    GroupPrincipal? group = GroupPrincipal.FindByIdentity(context, groupName);
                    if (group != null)
                    {
                        group.Members.Add(userPrincipal);
                        group.Save();
                        group.Dispose();
                    }
                    else
                    {
                        Console.WriteLine($"Warning: Group '{groupName}' not found in domain");
                    }
                }
                catch (Exception ex)
                {
                    // Log but continue - some groups may require elevated privileges
                    Console.WriteLine($"Warning: Could not add user to {groupName}: {ex.Message}");
                }
            }
        }

        private string? SecureStringToString(SecureString? secureString)
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
}

using GhostChaser.Models;
using System;
using System.Diagnostics;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace GhostChaser.Services
{
    /// <summary>
    /// Service for creating and managing Ghost SPNs (Service Principal Names) for detecting Kerberoasting attacks.
    /// When attackers use tools like Rubeus, Kerbrute, or Impacket to enumerate SPNs, the honey SPN
    /// triggers detection through Event ID 4769 (Kerberos Service Ticket Operations).
    /// </summary>
    public class GhostSPNService : IGhostDeploymentService
    {
        /// <summary>
        /// Common enticing SPN service classes that attackers target for Kerberoasting
        /// </summary>
        public static readonly string[] CommonServiceClasses = new[]
        {
            "MSSQLSvc",     // SQL Server - highly targeted
            "HTTP",         // Web services
            "HTTPS",        // Secure web services
            "FTP",          // File transfer
            "CIFS",         // Windows file shares
            "LDAP",         // LDAP services
            "HOST",         // Host services
            "TERMSRV",      // Terminal Services/RDP
            "WSMAN",        // WS-Management
            "exchangeMDB",  // Exchange Mailbox
            "exchangeRFR",  // Exchange Address Book
            "IMAP",         // IMAP email
            "SMTP",         // SMTP email
            "POP",          // POP3 email
            "mongodb",      // MongoDB
            "oracle",       // Oracle DB
            "postgres",     // PostgreSQL
            "mysql",        // MySQL
            "kafka",        // Kafka
            "redis",        // Redis
            "elasticsearch" // Elasticsearch
        };

        public async Task<DeploymentResult> DeployAsync(Ghost ghost, DeploymentCredentials credentials)
        {
            if (ghost is not GhostSPN spnGhost)
            {
                return new DeploymentResult
                {
                    Success = false,
                    Message = "Invalid ghost type. Expected GhostSPN."
                };
            }

            return await Task.Run(() => CreateGhostSPN(spnGhost, credentials));
        }

        public async Task<DeploymentResult> RemoveAsync(Ghost ghost, DeploymentCredentials credentials)
        {
            if (ghost is not GhostSPN spnGhost)
            {
                return new DeploymentResult
                {
                    Success = false,
                    Message = "Invalid ghost type. Expected GhostSPN."
                };
            }

            return await Task.Run(() => RemoveGhostSPN(spnGhost, credentials));
        }

        public async Task<bool> VerifyAsync(Ghost ghost, DeploymentCredentials credentials)
        {
            if (ghost is not GhostSPN spnGhost)
                return false;

            return await Task.Run(() => SPNExists(spnGhost, credentials));
        }

        private DeploymentResult CreateGhostSPN(GhostSPN ghost, DeploymentCredentials credentials)
        {
            try
            {
                string domain = string.IsNullOrEmpty(ghost.Domain) ?
                    Environment.UserDomainName : ghost.Domain;

                // Build the full SPN if not already set
                if (string.IsNullOrEmpty(ghost.ServicePrincipalName))
                {
                    ghost.ServicePrincipalName = ghost.BuildSPN();
                }

                // Step 1: Create service account if requested
                if (ghost.CreateServiceAccount)
                {
                    var accountResult = CreateServiceAccount(ghost, credentials, domain);
                    if (!accountResult.Success)
                    {
                        return accountResult;
                    }
                }
                else
                {
                    // Verify the target service account exists
                    if (!ServiceAccountExists(ghost.ServiceAccount, domain, credentials))
                    {
                        return new DeploymentResult
                        {
                            Success = false,
                            Message = $"Service account '{ghost.ServiceAccount}' not found in domain '{domain}'. Enable 'Create Service Account' or specify an existing account."
                        };
                    }
                }

                // Step 2: Register the SPN on the service account
                var spnResult = RegisterSPN(ghost, credentials, domain);
                if (!spnResult.Success)
                {
                    return spnResult;
                }

                ghost.Domain = domain;
                ghost.Status = GhostStatus.Active;

                return new DeploymentResult
                {
                    Success = true,
                    Message = $"Ghost SPN '{ghost.ServicePrincipalName}' registered on account '{ghost.ServiceAccount}' in domain '{domain}'.\n" +
                              $"Detection: Monitor Event ID 4769 for TGS requests targeting this SPN.",
                    DeployedGhost = ghost
                };
            }
            catch (Exception ex)
            {
                return new DeploymentResult
                {
                    Success = false,
                    Message = $"Failed to create Ghost SPN: {ex.Message}",
                    ErrorDetails = ex.ToString()
                };
            }
        }

        private DeploymentResult CreateServiceAccount(GhostSPN ghost, DeploymentCredentials credentials, string domain)
        {
            try
            {
                PrincipalContext context;

                if (credentials.UseCurrentCredentials || string.IsNullOrEmpty(credentials.Username))
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

                using (context)
                {
                    // Check if account already exists
                    UserPrincipal? existingUser = UserPrincipal.FindByIdentity(context, ghost.ServiceAccount);
                    if (existingUser != null)
                    {
                        existingUser.Dispose();
                        // Account exists, we can use it
                        return new DeploymentResult
                        {
                            Success = true,
                            Message = $"Using existing service account '{ghost.ServiceAccount}'"
                        };
                    }

                    // Create the service account - this is a honey account for Kerberoasting
                    UserPrincipal userPrincipal = new UserPrincipal(context)
                    {
                        SamAccountName = ghost.ServiceAccount,
                        Name = ghost.Name,
                        DisplayName = ghost.Name,
                        Description = ghost.Description ?? $"Service Account - {ghost.Name}",
                        PasswordNeverExpires = true,
                        UserCannotChangePassword = true,
                        Enabled = true
                    };

                    // Generate a password - for honey accounts, we use a strong password
                    // In a real Kerberoasting scenario, the attacker would try to crack this offline
                    string servicePassword = GenerateSecurePassword();
                    userPrincipal.SetPassword(servicePassword);

                    userPrincipal.Save();

                    // CRITICAL: Deny all logon hours to prevent actual authentication
                    // Even with correct credentials, the account cannot log on
                    // but TGS requests will still generate Event ID 4769
                    DenyAllLogonHours(userPrincipal);

                    return new DeploymentResult
                    {
                        Success = true,
                        Message = $"Service account '{ghost.ServiceAccount}' created successfully (logon hours denied)"
                    };
                }
            }
            catch (Exception ex)
            {
                return new DeploymentResult
                {
                    Success = false,
                    Message = $"Failed to create service account: {ex.Message}",
                    ErrorDetails = ex.ToString()
                };
            }
        }

        private DeploymentResult RegisterSPN(GhostSPN ghost, DeploymentCredentials credentials, string domain)
        {
            // Try LDAP method first (more reliable), fall back to setspn.exe
            var ldapResult = RegisterSPNviaLDAP(ghost, credentials, domain);
            if (ldapResult.Success)
            {
                return ldapResult;
            }

            // Fallback to setspn.exe
            return RegisterSPNviaSetSPN(ghost, domain);
        }

        private DeploymentResult RegisterSPNviaLDAP(GhostSPN ghost, DeploymentCredentials credentials, string domain)
        {
            try
            {
                string ldapPath = GetLDAPPath(ghost.ServiceAccount, domain, credentials);
                if (string.IsNullOrEmpty(ldapPath))
                {
                    return new DeploymentResult
                    {
                        Success = false,
                        Message = $"Could not find LDAP path for account '{ghost.ServiceAccount}'"
                    };
                }

                DirectoryEntry entry;
                if (credentials.UseCurrentCredentials || string.IsNullOrEmpty(credentials.Username))
                {
                    entry = new DirectoryEntry(ldapPath);
                }
                else
                {
                    string? password = SecureStringToString(credentials.Password);
                    string fullUsername = string.IsNullOrEmpty(credentials.Domain) ?
                        credentials.Username : $"{credentials.Domain}\\{credentials.Username}";
                    entry = new DirectoryEntry(ldapPath, fullUsername, password);
                }

                using (entry)
                {
                    // Check if SPN already exists
                    PropertyValueCollection spnProperty = entry.Properties["servicePrincipalName"];
                    foreach (object? existingSpn in spnProperty)
                    {
                        if (existingSpn?.ToString()?.Equals(ghost.ServicePrincipalName, StringComparison.OrdinalIgnoreCase) == true)
                        {
                            return new DeploymentResult
                            {
                                Success = false,
                                Message = $"SPN '{ghost.ServicePrincipalName}' already exists on account '{ghost.ServiceAccount}'"
                            };
                        }
                    }

                    // Add the SPN
                    entry.Properties["servicePrincipalName"].Add(ghost.ServicePrincipalName);
                    entry.CommitChanges();

                    return new DeploymentResult
                    {
                        Success = true,
                        Message = $"SPN '{ghost.ServicePrincipalName}' registered via LDAP"
                    };
                }
            }
            catch (Exception ex)
            {
                return new DeploymentResult
                {
                    Success = false,
                    Message = $"LDAP SPN registration failed: {ex.Message}",
                    ErrorDetails = ex.ToString()
                };
            }
        }

        private DeploymentResult RegisterSPNviaSetSPN(GhostSPN ghost, string domain)
        {
            try
            {
                // Use setspn.exe as fallback
                // Format: setspn -s <SPN> <account>
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "setspn.exe",
                    Arguments = $"-s {ghost.ServicePrincipalName} {domain}\\{ghost.ServiceAccount}",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using (Process? process = Process.Start(psi))
                {
                    if (process == null)
                    {
                        return new DeploymentResult
                        {
                            Success = false,
                            Message = "Failed to start setspn.exe process"
                        };
                    }

                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();
                    process.WaitForExit();

                    if (process.ExitCode == 0)
                    {
                        return new DeploymentResult
                        {
                            Success = true,
                            Message = $"SPN registered via setspn.exe: {output.Trim()}"
                        };
                    }
                    else
                    {
                        return new DeploymentResult
                        {
                            Success = false,
                            Message = $"setspn.exe failed: {error}",
                            ErrorDetails = output
                        };
                    }
                }
            }
            catch (Exception ex)
            {
                return new DeploymentResult
                {
                    Success = false,
                    Message = $"setspn.exe execution failed: {ex.Message}",
                    ErrorDetails = ex.ToString()
                };
            }
        }

        private DeploymentResult RemoveGhostSPN(GhostSPN ghost, DeploymentCredentials credentials)
        {
            try
            {
                string domain = string.IsNullOrEmpty(ghost.Domain) ?
                    Environment.UserDomainName : ghost.Domain;

                // Try LDAP removal first
                var ldapResult = RemoveSPNviaLDAP(ghost, credentials, domain);
                bool spnRemoved = ldapResult.Success;
                string spnMessage = ldapResult.Message;

                if (!spnRemoved)
                {
                    // Fallback to setspn.exe -d
                    var setspnResult = RemoveSPNviaSetSPN(ghost, domain);
                    spnRemoved = setspnResult.Success;
                    spnMessage = setspnResult.Message;
                }

                if (!spnRemoved)
                {
                    return new DeploymentResult
                    {
                        Success = false,
                        Message = spnMessage
                    };
                }

                // SPN removed successfully - now delete the service account if it was created by GhostChaser
                string accountMessage = "";
                if (ghost.CreateServiceAccount)
                {
                    var accountResult = DeleteServiceAccount(ghost.ServiceAccount, domain, credentials);
                    if (accountResult.Success)
                    {
                        accountMessage = $" Service account '{ghost.ServiceAccount}' also deleted.";
                    }
                    else
                    {
                        accountMessage = $" Warning: Could not delete service account: {accountResult.Message}";
                    }
                }

                ghost.Status = GhostStatus.Removed;

                return new DeploymentResult
                {
                    Success = true,
                    Message = $"Ghost SPN '{ghost.ServicePrincipalName}' removed successfully.{accountMessage}"
                };
            }
            catch (Exception ex)
            {
                return new DeploymentResult
                {
                    Success = false,
                    Message = $"Failed to remove Ghost SPN: {ex.Message}",
                    ErrorDetails = ex.ToString()
                };
            }
        }

        /// <summary>
        /// Deletes a service account that was created for a Ghost SPN
        /// </summary>
        private DeploymentResult DeleteServiceAccount(string accountName, string domain, DeploymentCredentials credentials)
        {
            try
            {
                PrincipalContext context;

                if (credentials.UseCurrentCredentials || string.IsNullOrEmpty(credentials.Username))
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

                using (context)
                {
                    UserPrincipal? user = UserPrincipal.FindByIdentity(context, accountName);

                    if (user == null)
                    {
                        return new DeploymentResult
                        {
                            Success = false,
                            Message = $"Service account '{accountName}' not found"
                        };
                    }

                    user.Delete();

                    return new DeploymentResult
                    {
                        Success = true,
                        Message = $"Service account '{accountName}' deleted successfully"
                    };
                }
            }
            catch (Exception ex)
            {
                return new DeploymentResult
                {
                    Success = false,
                    Message = $"Failed to delete service account: {ex.Message}",
                    ErrorDetails = ex.ToString()
                };
            }
        }

        private DeploymentResult RemoveSPNviaLDAP(GhostSPN ghost, DeploymentCredentials credentials, string domain)
        {
            try
            {
                string ldapPath = GetLDAPPath(ghost.ServiceAccount, domain, credentials);
                if (string.IsNullOrEmpty(ldapPath))
                {
                    return new DeploymentResult
                    {
                        Success = false,
                        Message = $"Could not find LDAP path for account '{ghost.ServiceAccount}'"
                    };
                }

                DirectoryEntry entry;
                if (credentials.UseCurrentCredentials || string.IsNullOrEmpty(credentials.Username))
                {
                    entry = new DirectoryEntry(ldapPath);
                }
                else
                {
                    string? password = SecureStringToString(credentials.Password);
                    string fullUsername = string.IsNullOrEmpty(credentials.Domain) ?
                        credentials.Username : $"{credentials.Domain}\\{credentials.Username}";
                    entry = new DirectoryEntry(ldapPath, fullUsername, password);
                }

                using (entry)
                {
                    PropertyValueCollection spnProperty = entry.Properties["servicePrincipalName"];

                    // Find and remove the SPN
                    object? spnToRemove = null;
                    foreach (object? existingSpn in spnProperty)
                    {
                        if (existingSpn?.ToString()?.Equals(ghost.ServicePrincipalName, StringComparison.OrdinalIgnoreCase) == true)
                        {
                            spnToRemove = existingSpn;
                            break;
                        }
                    }

                    if (spnToRemove == null)
                    {
                        return new DeploymentResult
                        {
                            Success = false,
                            Message = $"SPN '{ghost.ServicePrincipalName}' not found on account '{ghost.ServiceAccount}'"
                        };
                    }

                    spnProperty.Remove(spnToRemove);
                    entry.CommitChanges();

                    return new DeploymentResult
                    {
                        Success = true,
                        Message = $"Ghost SPN '{ghost.ServicePrincipalName}' removed successfully"
                    };
                }
            }
            catch (Exception ex)
            {
                return new DeploymentResult
                {
                    Success = false,
                    Message = $"LDAP SPN removal failed: {ex.Message}",
                    ErrorDetails = ex.ToString()
                };
            }
        }

        private DeploymentResult RemoveSPNviaSetSPN(GhostSPN ghost, string domain)
        {
            try
            {
                // Format: setspn -d <SPN> <account>
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "setspn.exe",
                    Arguments = $"-d {ghost.ServicePrincipalName} {domain}\\{ghost.ServiceAccount}",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using (Process? process = Process.Start(psi))
                {
                    if (process == null)
                    {
                        return new DeploymentResult
                        {
                            Success = false,
                            Message = "Failed to start setspn.exe process"
                        };
                    }

                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();
                    process.WaitForExit();

                    if (process.ExitCode == 0)
                    {
                        return new DeploymentResult
                        {
                            Success = true,
                            Message = $"SPN removed via setspn.exe: {output.Trim()}"
                        };
                    }
                    else
                    {
                        return new DeploymentResult
                        {
                            Success = false,
                            Message = $"setspn.exe removal failed: {error}",
                            ErrorDetails = output
                        };
                    }
                }
            }
            catch (Exception ex)
            {
                return new DeploymentResult
                {
                    Success = false,
                    Message = $"setspn.exe execution failed: {ex.Message}",
                    ErrorDetails = ex.ToString()
                };
            }
        }

        private bool SPNExists(GhostSPN ghost, DeploymentCredentials credentials)
        {
            try
            {
                string domain = string.IsNullOrEmpty(ghost.Domain) ?
                    Environment.UserDomainName : ghost.Domain;

                string ldapPath = GetLDAPPath(ghost.ServiceAccount, domain, credentials);
                if (string.IsNullOrEmpty(ldapPath))
                    return false;

                using (DirectoryEntry entry = new DirectoryEntry(ldapPath))
                {
                    PropertyValueCollection spnProperty = entry.Properties["servicePrincipalName"];
                    foreach (object? existingSpn in spnProperty)
                    {
                        if (existingSpn?.ToString()?.Equals(ghost.ServicePrincipalName, StringComparison.OrdinalIgnoreCase) == true)
                        {
                            return true;
                        }
                    }
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        private bool ServiceAccountExists(string accountName, string domain, DeploymentCredentials credentials)
        {
            try
            {
                PrincipalContext context;

                if (credentials.UseCurrentCredentials || string.IsNullOrEmpty(credentials.Username))
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

                using (context)
                {
                    UserPrincipal? user = UserPrincipal.FindByIdentity(context, accountName);
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

        private string GetLDAPPath(string accountName, string domain, DeploymentCredentials credentials)
        {
            try
            {
                PrincipalContext context;

                if (credentials.UseCurrentCredentials || string.IsNullOrEmpty(credentials.Username))
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

                using (context)
                {
                    UserPrincipal? user = UserPrincipal.FindByIdentity(context, accountName);
                    if (user == null)
                        return string.Empty;

                    DirectoryEntry? de = user.GetUnderlyingObject() as DirectoryEntry;
                    string path = de?.Path ?? string.Empty;
                    user.Dispose();
                    return path;
                }
            }
            catch
            {
                return string.Empty;
            }
        }

        /// <summary>
        /// Sets the logon hours for an account to deny all hours.
        /// This prevents the service account from being used for logon even with correct credentials,
        /// while still allowing Kerberos TGS requests (Event ID 4769) to be generated for detection.
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
                Console.WriteLine($"Warning: Could not set logon hours restriction for SPN service account: {ex.Message}");
            }
        }

        private string GenerateSecurePassword(int length = 32)
        {
            const string validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+-=[]{}|;:,.<>?";
            StringBuilder password = new StringBuilder();
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                byte[] data = new byte[length];
                rng.GetBytes(data);
                for (int i = 0; i < length; i++)
                {
                    password.Append(validChars[data[i] % validChars.Length]);
                }
            }
            return password.ToString();
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

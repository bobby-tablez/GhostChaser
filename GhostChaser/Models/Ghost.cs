using System;
using System.Collections.Generic;

namespace GhostChaser.Models
{
    /// <summary>
    /// Base class representing a Ghost (canary) entity
    /// </summary>
    public abstract class Ghost
    {
        public Guid Id { get; set; }
        public GhostType Type { get; set; }
        public string Name { get; set; } = string.Empty;
        public string TargetSystem { get; set; } = string.Empty;
        public DateTime CreatedDate { get; set; }
        public GhostStatus Status { get; set; }
        public string? Description { get; set; }
        public string CreatedBy { get; set; } = string.Empty;

        protected Ghost()
        {
            Id = Guid.NewGuid();
            CreatedDate = DateTime.UtcNow;
            Status = GhostStatus.Created;
        }
    }

    /// <summary>
    /// Represents a Ghost user account (canary account)
    /// </summary>
    public class GhostAccount : Ghost
    {
        public string Username { get; set; } = string.Empty;
        public string Domain { get; set; } = string.Empty;
        public bool IsLocalAccount { get; set; }
        public string? OrganizationalUnit { get; set; }

        /// <summary>
        /// Group memberships to add the Ghost account to.
        /// Makes the account appear more enticing to attackers.
        /// </summary>
        public List<string> GroupMemberships { get; set; } = new List<string>();

        public GhostAccount()
        {
            Type = GhostType.Account;
        }
    }

    /// <summary>
    /// Represents a Ghost file (canary file)
    /// </summary>
    public class GhostFile : Ghost
    {
        public string FilePath { get; set; } = string.Empty;
        public string FileExtension { get; set; } = string.Empty;
        public long FileSize { get; set; }
        public bool HasAuditingEnabled { get; set; }

        public GhostFile()
        {
            Type = GhostType.File;
        }
    }

    /// <summary>
    /// Represents a Ghost network share (canary share)
    /// </summary>
    public class GhostShare : Ghost
    {
        public string ShareName { get; set; } = string.Empty;
        public string SharePath { get; set; } = string.Empty;
        public string? ShareDescription { get; set; }
        public bool HasAuditingEnabled { get; set; }

        /// <summary>
        /// List of bait files to create in the share.
        /// Selected by user to make the share appear enticing.
        /// </summary>
        public List<string> BaitFiles { get; set; } = new List<string>();

        public GhostShare()
        {
            Type = GhostType.Share;
        }
    }

    /// <summary>
    /// Represents a Ghost SPN (Service Principal Name) for detecting Kerberoasting attacks.
    /// When attackers enumerate SPNs using tools like Rubeus, Kerbrute, or Impacket,
    /// the honey SPN triggers detection through Event ID 4769 (TGS requests).
    /// </summary>
    public class GhostSPN : Ghost
    {
        /// <summary>
        /// The service class (e.g., MSSQLSvc, HTTP, FTP, LDAP, CIFS)
        /// </summary>
        public string ServiceClass { get; set; } = string.Empty;

        /// <summary>
        /// The service host/instance (e.g., sqlserver.domain.com, webapp.domain.com:1433)
        /// </summary>
        public string ServiceHost { get; set; } = string.Empty;

        /// <summary>
        /// The full SPN string (e.g., MSSQLSvc/sqlserver.domain.com:1433)
        /// </summary>
        public string ServicePrincipalName { get; set; } = string.Empty;

        /// <summary>
        /// The service account the SPN is registered to
        /// </summary>
        public string ServiceAccount { get; set; } = string.Empty;

        /// <summary>
        /// Domain where the SPN is registered
        /// </summary>
        public string Domain { get; set; } = string.Empty;

        /// <summary>
        /// Whether to create a new service account for the SPN or use existing
        /// </summary>
        public bool CreateServiceAccount { get; set; }

        /// <summary>
        /// Whether Kerberos auditing is enabled for this SPN (Event ID 4769)
        /// </summary>
        public bool HasKerberosAuditingEnabled { get; set; }

        public GhostSPN()
        {
            Type = GhostType.SPN;
        }

        /// <summary>
        /// Builds the full SPN string from service class and host
        /// </summary>
        public string BuildSPN()
        {
            return $"{ServiceClass}/{ServiceHost}";
        }
    }
}

using System;

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

        public GhostShare()
        {
            Type = GhostType.Share;
        }
    }
}

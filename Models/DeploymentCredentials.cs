using System;
using System.Security;

namespace GhostChaser.Models
{
    /// <summary>
    /// Credentials for deploying Ghosts to target systems
    /// </summary>
    public class DeploymentCredentials : IDisposable
    {
        public string Username { get; set; } = string.Empty;
        public SecureString? Password { get; set; }
        public string Domain { get; set; } = string.Empty;
        public bool UseCurrentCredentials { get; set; }

        public void Dispose()
        {
            Password?.Dispose();
        }
    }
}

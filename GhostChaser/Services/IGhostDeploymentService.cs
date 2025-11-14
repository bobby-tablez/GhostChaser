using GhostChaser.Models;
using System.Threading.Tasks;

namespace GhostChaser.Services
{
    /// <summary>
    /// Interface for Ghost deployment services
    /// </summary>
    public interface IGhostDeploymentService
    {
        Task<DeploymentResult> DeployAsync(Ghost ghost, DeploymentCredentials credentials);
        Task<DeploymentResult> RemoveAsync(Ghost ghost, DeploymentCredentials credentials);
        Task<bool> VerifyAsync(Ghost ghost, DeploymentCredentials credentials);
    }

    /// <summary>
    /// Result of a Ghost deployment operation
    /// </summary>
    public class DeploymentResult
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public string? ErrorDetails { get; set; }
        public Ghost? DeployedGhost { get; set; }
    }
}

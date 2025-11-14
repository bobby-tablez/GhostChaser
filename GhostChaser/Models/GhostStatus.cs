namespace GhostChaser.Models
{
    /// <summary>
    /// Status of a Ghost deployment
    /// </summary>
    public enum GhostStatus
    {
        Created,
        Active,
        Triggered,
        Failed,
        Removed
    }
}

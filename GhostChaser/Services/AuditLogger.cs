using GhostChaser.Models;
using System;
using System.IO;
using System.Text.Json;

namespace GhostChaser.Services
{
    /// <summary>
    /// Service for logging Ghost deployment activities and audit events
    /// </summary>
    public class AuditLogger
    {
        private readonly string _logDirectory;
        private readonly string _logFilePath;
        private static readonly object _logLock = new object();

        public AuditLogger()
        {
            _logDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "GhostChaser",
                "Logs"
            );

            Directory.CreateDirectory(_logDirectory);

            _logFilePath = Path.Combine(_logDirectory, $"GhostChaser_Audit_{DateTime.Now:yyyyMMdd}.log");
        }

        public void LogGhostCreation(Ghost ghost, string username)
        {
            var logEntry = new
            {
                Timestamp = DateTime.UtcNow,
                EventType = "GhostCreated",
                GhostId = ghost.Id,
                GhostType = ghost.Type.ToString(),
                GhostName = ghost.Name,
                TargetSystem = ghost.TargetSystem,
                CreatedBy = username,
                Details = GetGhostDetails(ghost)
            };

            WriteLog(logEntry);
        }

        public void LogGhostRemoval(Ghost ghost, string username)
        {
            var logEntry = new
            {
                Timestamp = DateTime.UtcNow,
                EventType = "GhostRemoved",
                GhostId = ghost.Id,
                GhostType = ghost.Type.ToString(),
                GhostName = ghost.Name,
                TargetSystem = ghost.TargetSystem,
                RemovedBy = username
            };

            WriteLog(logEntry);
        }

        public void LogDeploymentSuccess(DeploymentResult result, string username)
        {
            var logEntry = new
            {
                Timestamp = DateTime.UtcNow,
                EventType = "DeploymentSuccess",
                Message = result.Message,
                DeployedBy = username
            };

            WriteLog(logEntry);
        }

        public void LogDeploymentFailure(DeploymentResult result, string username)
        {
            var logEntry = new
            {
                Timestamp = DateTime.UtcNow,
                EventType = "DeploymentFailure",
                Message = result.Message,
                ErrorDetails = result.ErrorDetails,
                AttemptedBy = username
            };

            WriteLog(logEntry);
        }

        public void LogError(string operation, Exception exception, string username)
        {
            var logEntry = new
            {
                Timestamp = DateTime.UtcNow,
                EventType = "Error",
                Operation = operation,
                ErrorMessage = exception.Message,
                StackTrace = exception.StackTrace,
                User = username
            };

            WriteLog(logEntry);
        }

        public void LogInformation(string message, string username)
        {
            var logEntry = new
            {
                Timestamp = DateTime.UtcNow,
                EventType = "Information",
                Message = message,
                User = username
            };

            WriteLog(logEntry);
        }

        private void WriteLog(object logEntry)
        {
            try
            {
                lock (_logLock)
                {
                    string jsonLog = JsonSerializer.Serialize(logEntry, new JsonSerializerOptions
                    {
                        WriteIndented = false
                    });

                    File.AppendAllText(_logFilePath, jsonLog + Environment.NewLine);
                }
            }
            catch (Exception ex)
            {
                // If logging fails, write to console as fallback
                Console.WriteLine($"Failed to write to audit log: {ex.Message}");
            }
        }

        private object GetGhostDetails(Ghost ghost)
        {
            return ghost switch
            {
                GhostAccount account => new
                {
                    Username = account.Username,
                    Domain = account.Domain,
                    IsLocalAccount = account.IsLocalAccount,
                    OrganizationalUnit = account.OrganizationalUnit
                },
                GhostFile file => new
                {
                    FilePath = file.FilePath,
                    FileExtension = file.FileExtension,
                    HasAuditingEnabled = file.HasAuditingEnabled
                },
                GhostShare share => new
                {
                    ShareName = share.ShareName,
                    SharePath = share.SharePath,
                    HasAuditingEnabled = share.HasAuditingEnabled
                },
                _ => new { }
            };
        }

        public string GetLogDirectory() => _logDirectory;
        public string GetCurrentLogFile() => _logFilePath;
    }
}

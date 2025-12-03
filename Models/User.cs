/*
 * =============================================================================
 * User Entity Model
 * =============================================================================
 * 
 * Represents a user in the authentication system.
 * Stores user credentials and MFA settings securely.
 * 
 * Security Features:
 * - Password is stored as a BCrypt hash, never in plain text
 * - MFA secret key is stored for TOTP generation
 * =============================================================================
 */

using System.ComponentModel.DataAnnotations;

namespace SecureLoginSystem.Models
{
    /// <summary>
    /// User entity representing authenticated users in the system.
    /// </summary>
    public class User
    {
        /// <summary>
        /// Unique identifier for the user.
        /// </summary>
        [Key]
        public int Id { get; set; }

        /// <summary>
        /// Username for login. Must be unique.
        /// </summary>
        [Required]
        [StringLength(50, MinimumLength = 3)]
        public string Username { get; set; } = string.Empty;

        /// <summary>
        /// Email address for the user. Must be unique and valid format.
        /// </summary>
        [Required]
        [EmailAddress]
        [StringLength(100)]
        public string Email { get; set; } = string.Empty;

        /// <summary>
        /// BCrypt hashed password. Never store plain text passwords.
        /// </summary>
        [Required]
        public string PasswordHash { get; set; } = string.Empty;

        /// <summary>
        /// Indicates if Multi-Factor Authentication is enabled for this user.
        /// </summary>
        public bool IsMfaEnabled { get; set; } = false;

        /// <summary>
        /// Secret key for TOTP (Time-based One-Time Password) generation.
        /// Used with authenticator apps like Google Authenticator.
        /// </summary>
        public string? MfaSecretKey { get; set; }

        /// <summary>
        /// Timestamp when the user account was created.
        /// </summary>
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Timestamp of the user's last successful login.
        /// </summary>
        public DateTime? LastLoginAt { get; set; }

        /// <summary>
        /// Number of consecutive failed login attempts.
        /// Used for account lockout protection.
        /// </summary>
        public int FailedLoginAttempts { get; set; } = 0;

        /// <summary>
        /// Timestamp until which the account is locked.
        /// Null means the account is not locked.
        /// </summary>
        public DateTime? LockoutEnd { get; set; }
    }
}


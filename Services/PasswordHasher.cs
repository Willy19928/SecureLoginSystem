/*
 * =============================================================================
 * Password Hasher Service
 * =============================================================================
 * 
 * Implements secure password hashing using BCrypt algorithm.
 * 
 * Security Features:
 * - BCrypt is designed specifically for password hashing
 * - Includes built-in salt generation
 * - Configurable work factor for future-proofing
 * - Resistant to rainbow table attacks
 * - Computationally expensive to prevent brute force attacks
 * =============================================================================
 */

namespace SecureLoginSystem.Services
{
    /// <summary>
    /// BCrypt-based password hashing service.
    /// </summary>
    public class PasswordHasher : IPasswordHasher
    {
        // Work factor determines the computational cost of hashing.
        // Higher values = more secure but slower.
        // 12 is recommended for production (2^12 iterations).
        private const int WorkFactor = 12;

        /// <summary>
        /// Hash a password using BCrypt with automatic salt generation.
        /// </summary>
        /// <param name="password">Plain text password</param>
        /// <returns>BCrypt hash string including salt</returns>
        public string HashPassword(string password)
        {
            // BCrypt.HashPassword automatically generates a cryptographically
            // secure random salt and includes it in the output hash.
            // Format: $2a$[cost]$[22 char salt][31 char hash]
            return BCrypt.Net.BCrypt.HashPassword(password, WorkFactor);
        }

        /// <summary>
        /// Verify a password against a stored BCrypt hash.
        /// </summary>
        /// <param name="password">Plain text password to verify</param>
        /// <param name="hashedPassword">Stored BCrypt hash</param>
        /// <returns>True if password matches hash, false otherwise</returns>
        public bool VerifyPassword(string password, string hashedPassword)
        {
            try
            {
                // BCrypt.Verify extracts the salt from the hash and
                // computes the hash of the provided password, then
                // performs a timing-safe comparison.
                return BCrypt.Net.BCrypt.Verify(password, hashedPassword);
            }
            catch
            {
                // Return false if hash format is invalid or any error occurs.
                // Don't expose error details (security through obscurity).
                return false;
            }
        }
    }
}


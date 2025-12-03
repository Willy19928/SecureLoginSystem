/*
 * =============================================================================
 * Password Hasher Interface
 * =============================================================================
 * 
 * Interface for password hashing operations.
 * Allows for dependency injection and easy testing.
 * =============================================================================
 */

namespace SecureLoginSystem.Services
{
    /// <summary>
    /// Interface for secure password hashing operations.
    /// </summary>
    public interface IPasswordHasher
    {
        /// <summary>
        /// Hash a plain text password using BCrypt.
        /// </summary>
        /// <param name="password">Plain text password to hash</param>
        /// <returns>BCrypt hashed password string</returns>
        string HashPassword(string password);

        /// <summary>
        /// Verify a plain text password against a stored hash.
        /// </summary>
        /// <param name="password">Plain text password to verify</param>
        /// <param name="hashedPassword">Stored BCrypt hash to compare against</param>
        /// <returns>True if password matches, false otherwise</returns>
        bool VerifyPassword(string password, string hashedPassword);
    }
}


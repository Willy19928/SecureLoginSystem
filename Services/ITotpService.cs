/*
 * =============================================================================
 * TOTP Service Interface
 * =============================================================================
 * 
 * Interface for Time-based One-Time Password operations.
 * Used for Multi-Factor Authentication (MFA).
 * =============================================================================
 */

namespace SecureLoginSystem.Services
{
    /// <summary>
    /// Interface for TOTP (Time-based One-Time Password) operations.
    /// </summary>
    public interface ITotpService
    {
        /// <summary>
        /// Generate a new secret key for TOTP setup.
        /// </summary>
        /// <returns>Base32 encoded secret key</returns>
        string GenerateSecretKey();

        /// <summary>
        /// Generate a QR code image for authenticator app scanning.
        /// </summary>
        /// <param name="secretKey">Base32 secret key</param>
        /// <param name="email">User's email (used in authenticator app label)</param>
        /// <param name="issuer">Application name shown in authenticator</param>
        /// <returns>Base64 encoded PNG image data</returns>
        string GenerateQrCodeUri(string secretKey, string email, string issuer = "SecureLoginSystem");

        /// <summary>
        /// Verify a TOTP code against the secret key.
        /// </summary>
        /// <param name="secretKey">User's stored secret key</param>
        /// <param name="code">6-digit code from authenticator app</param>
        /// <returns>True if code is valid, false otherwise</returns>
        bool VerifyCode(string secretKey, string code);
    }
}


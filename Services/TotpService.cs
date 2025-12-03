/*
 * =============================================================================
 * TOTP Service Implementation
 * =============================================================================
 * 
 * Implements Time-based One-Time Password (TOTP) for MFA.
 * Compatible with Google Authenticator, Microsoft Authenticator, etc.
 * 
 * Security Features:
 * - RFC 6238 compliant TOTP implementation
 * - 30-second time window
 * - 6-digit codes
 * - Includes time drift tolerance
 * =============================================================================
 */

using OtpNet;
using QRCoder;

namespace SecureLoginSystem.Services
{
    /// <summary>
    /// TOTP service for Multi-Factor Authentication.
    /// </summary>
    public class TotpService : ITotpService
    {
        // TOTP configuration constants
        private const int SecretKeyLength = 20;  // 160 bits as recommended by RFC 4226
        private const int TimeStepSeconds = 30;  // Standard TOTP time window
        private const int CodeDigits = 6;        // Standard 6-digit codes

        /// <summary>
        /// Generate a new random secret key for TOTP.
        /// </summary>
        /// <returns>Base32 encoded secret key suitable for authenticator apps</returns>
        public string GenerateSecretKey()
        {
            // Generate cryptographically secure random bytes
            var key = KeyGeneration.GenerateRandomKey(SecretKeyLength);
            
            // Convert to Base32 for compatibility with authenticator apps
            return Base32Encoding.ToString(key);
        }

        /// <summary>
        /// Generate a QR code image for easy authenticator app setup.
        /// </summary>
        /// <param name="secretKey">Base32 encoded secret key</param>
        /// <param name="email">User's email for identification</param>
        /// <param name="issuer">Application name (shown in authenticator)</param>
        /// <returns>Base64 encoded PNG image for embedding in HTML</returns>
        public string GenerateQrCodeUri(string secretKey, string email, string issuer = "SecureLoginSystem")
        {
            // Create otpauth:// URI format for authenticator apps
            // Format: otpauth://totp/{issuer}:{email}?secret={key}&issuer={issuer}&algorithm=SHA1&digits=6&period=30
            var uri = $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(email)}" +
                     $"?secret={secretKey}" +
                     $"&issuer={Uri.EscapeDataString(issuer)}" +
                     $"&algorithm=SHA1" +
                     $"&digits={CodeDigits}" +
                     $"&period={TimeStepSeconds}";

            // Generate QR code using QRCoder library
            using var qrGenerator = new QRCodeGenerator();
            using var qrCodeData = qrGenerator.CreateQrCode(uri, QRCodeGenerator.ECCLevel.Q);
            using var qrCode = new PngByteQRCode(qrCodeData);
            
            // Get PNG bytes and convert to base64 for HTML embedding
            var qrCodeBytes = qrCode.GetGraphic(5);  // 5 = pixels per module
            return $"data:image/png;base64,{Convert.ToBase64String(qrCodeBytes)}";
        }

        /// <summary>
        /// Verify a TOTP code against the user's secret key.
        /// </summary>
        /// <param name="secretKey">User's stored Base32 secret key</param>
        /// <param name="code">6-digit code from authenticator app</param>
        /// <returns>True if code is valid within time window, false otherwise</returns>
        public bool VerifyCode(string secretKey, string code)
        {
            try
            {
                // Decode the Base32 secret key
                var keyBytes = Base32Encoding.ToBytes(secretKey);
                
                // Create TOTP instance with standard configuration
                var totp = new Totp(keyBytes, step: TimeStepSeconds, totpSize: CodeDigits);
                
                // Verify the code with a tolerance window of ±1 time step (±30 seconds)
                // This accommodates minor time drift between server and authenticator
                return totp.VerifyTotp(code, out _, new VerificationWindow(previous: 1, future: 1));
            }
            catch
            {
                // Return false if any error occurs (invalid key format, etc.)
                return false;
            }
        }
    }
}


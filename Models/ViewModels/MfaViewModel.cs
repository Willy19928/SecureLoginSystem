/*
 * =============================================================================
 * MFA View Models
 * =============================================================================
 * 
 * Data transfer objects for Multi-Factor Authentication flows.
 * Handles both MFA setup and verification processes.
 * 
 * Security Features:
 * - TOTP code validation (6 digits)
 * - QR code display for authenticator app setup
 * =============================================================================
 */

using System.ComponentModel.DataAnnotations;

namespace SecureLoginSystem.Models.ViewModels
{
    /// <summary>
    /// View model for MFA setup process.
    /// </summary>
    public class MfaSetupViewModel
    {
        /// <summary>
        /// Base64 encoded QR code image for authenticator app scanning.
        /// </summary>
        public string QrCodeImage { get; set; } = string.Empty;

        /// <summary>
        /// Manual entry key for authenticator app (if QR scanning fails).
        /// </summary>
        public string ManualEntryKey { get; set; } = string.Empty;

        /// <summary>
        /// Verification code from authenticator app to confirm setup.
        /// </summary>
        [Required(ErrorMessage = "Verification code is required")]
        [StringLength(6, MinimumLength = 6, ErrorMessage = "Code must be exactly 6 digits")]
        [RegularExpression(@"^\d{6}$", ErrorMessage = "Code must be exactly 6 digits")]
        [Display(Name = "Verification Code")]
        public string VerificationCode { get; set; } = string.Empty;
    }

    /// <summary>
    /// View model for MFA verification during login.
    /// </summary>
    public class MfaVerifyViewModel
    {
        /// <summary>
        /// Username being verified (hidden field).
        /// </summary>
        public string Username { get; set; } = string.Empty;

        /// <summary>
        /// TOTP code from authenticator app.
        /// </summary>
        [Required(ErrorMessage = "Verification code is required")]
        [StringLength(6, MinimumLength = 6, ErrorMessage = "Code must be exactly 6 digits")]
        [RegularExpression(@"^\d{6}$", ErrorMessage = "Code must be exactly 6 digits")]
        [Display(Name = "Authentication Code")]
        public string Code { get; set; } = string.Empty;
    }
}


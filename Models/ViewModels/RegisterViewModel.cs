/*
 * =============================================================================
 * Register View Model
 * =============================================================================
 * 
 * Data transfer object for user registration form.
 * Includes validation attributes for input security.
 * 
 * Security Features:
 * - Input validation to prevent malicious data
 * - Password strength requirements enforced
 * - XSS prevention through data annotations
 * =============================================================================
 */

using System.ComponentModel.DataAnnotations;

namespace SecureLoginSystem.Models.ViewModels
{
    /// <summary>
    /// View model for user registration with validation rules.
    /// </summary>
    public class RegisterViewModel
    {
        /// <summary>
        /// Username must be 3-50 characters, alphanumeric only.
        /// </summary>
        [Required(ErrorMessage = "Username is required")]
        [StringLength(50, MinimumLength = 3, ErrorMessage = "Username must be 3-50 characters")]
        [RegularExpression(@"^[a-zA-Z0-9_]+$", ErrorMessage = "Username can only contain letters, numbers, and underscores")]
        [Display(Name = "Username")]
        public string Username { get; set; } = string.Empty;

        /// <summary>
        /// Valid email address format required.
        /// </summary>
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email address format")]
        [StringLength(100, ErrorMessage = "Email cannot exceed 100 characters")]
        [Display(Name = "Email Address")]
        public string Email { get; set; } = string.Empty;

        /// <summary>
        /// Password must meet strength requirements:
        /// - Minimum 8 characters
        /// - At least one uppercase letter
        /// - At least one lowercase letter
        /// - At least one digit
        /// - At least one special character
        /// </summary>
        [Required(ErrorMessage = "Password is required")]
        [StringLength(100, MinimumLength = 8, ErrorMessage = "Password must be at least 8 characters")]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",
            ErrorMessage = "Password must contain at least one uppercase, one lowercase, one digit, and one special character (@$!%*?&)")]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; } = string.Empty;

        /// <summary>
        /// Must match the Password field.
        /// </summary>
        [Required(ErrorMessage = "Please confirm your password")]
        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "Passwords do not match")]
        [Display(Name = "Confirm Password")]
        public string ConfirmPassword { get; set; } = string.Empty;

        /// <summary>
        /// Optional: Enable MFA during registration.
        /// </summary>
        [Display(Name = "Enable Two-Factor Authentication")]
        public bool EnableMfa { get; set; } = false;
    }
}


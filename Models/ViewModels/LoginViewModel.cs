/*
 * =============================================================================
 * Login View Model
 * =============================================================================
 * 
 * Data transfer object for user login form.
 * Includes validation to ensure required fields are provided.
 * 
 * Security Features:
 * - Input validation prevents empty submissions
 * - No password requirements exposed (security through obscurity)
 * =============================================================================
 */

using System.ComponentModel.DataAnnotations;

namespace SecureLoginSystem.Models.ViewModels
{
    /// <summary>
    /// View model for user login with validation rules.
    /// </summary>
    public class LoginViewModel
    {
        /// <summary>
        /// Username for authentication.
        /// </summary>
        [Required(ErrorMessage = "Username is required")]
        [Display(Name = "Username")]
        public string Username { get; set; } = string.Empty;

        /// <summary>
        /// Password for authentication.
        /// </summary>
        [Required(ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; } = string.Empty;

        /// <summary>
        /// Remember user session for extended period.
        /// </summary>
        [Display(Name = "Remember me")]
        public bool RememberMe { get; set; } = false;
    }
}


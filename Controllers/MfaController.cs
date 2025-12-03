/*
 * =============================================================================
 * MFA Controller
 * =============================================================================
 * 
 * Handles Multi-Factor Authentication setup and verification.
 * Uses TOTP (Time-based One-Time Password) compatible with
 * Google Authenticator, Microsoft Authenticator, etc.
 * 
 * Security Features:
 * - TOTP with 30-second time window
 * - QR code generation for easy setup
 * - Verification required before enabling MFA
 * - Session-based state management
 * =============================================================================
 */

using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SecureLoginSystem.Data;
using SecureLoginSystem.Models.ViewModels;
using SecureLoginSystem.Services;

namespace SecureLoginSystem.Controllers
{
    /// <summary>
    /// Controller for MFA operations.
    /// </summary>
    public class MfaController : Controller
    {
        private readonly AppDbContext _context;
        private readonly ITotpService _totpService;

        public MfaController(AppDbContext context, ITotpService totpService)
        {
            _context = context;
            _totpService = totpService;
        }

        // =========================================================================
        // MFA SETUP
        // =========================================================================

        /// <summary>
        /// Display MFA setup page with QR code.
        /// GET: /Mfa/SetupMfa
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> SetupMfa()
        {
            // Check for pending MFA setup from registration
            var pendingUserId = HttpContext.Session.GetInt32("PendingMfaSetup");
            
            // Also check if logged in user wants to enable MFA
            var loggedInUserId = HttpContext.Session.GetInt32("UserId");
            
            var userId = pendingUserId ?? loggedInUserId;
            
            if (userId == null)
            {
                return RedirectToAction("Login", "Account");
            }

            var user = await _context.Users.FindAsync(userId);
            if (user == null)
            {
                return RedirectToAction("Login", "Account");
            }

            // Generate new secret if not exists
            if (string.IsNullOrEmpty(user.MfaSecretKey))
            {
                user.MfaSecretKey = _totpService.GenerateSecretKey();
                await _context.SaveChangesAsync();
            }

            // Create view model with QR code
            var model = new MfaSetupViewModel
            {
                QrCodeImage = _totpService.GenerateQrCodeUri(user.MfaSecretKey, user.Email),
                ManualEntryKey = FormatSecretKey(user.MfaSecretKey)
            };

            return View(model);
        }

        /// <summary>
        /// Process MFA setup verification.
        /// POST: /Mfa/SetupMfa
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SetupMfa(MfaSetupViewModel model)
        {
            // Get user ID from session
            var pendingUserId = HttpContext.Session.GetInt32("PendingMfaSetup");
            var loggedInUserId = HttpContext.Session.GetInt32("UserId");
            var userId = pendingUserId ?? loggedInUserId;

            if (userId == null)
            {
                return RedirectToAction("Login", "Account");
            }

            var user = await _context.Users.FindAsync(userId);
            if (user == null || string.IsNullOrEmpty(user.MfaSecretKey))
            {
                return RedirectToAction("Login", "Account");
            }

            // Regenerate QR code for display if validation fails
            model.QrCodeImage = _totpService.GenerateQrCodeUri(user.MfaSecretKey, user.Email);
            model.ManualEntryKey = FormatSecretKey(user.MfaSecretKey);

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // Verify the TOTP code
            if (!_totpService.VerifyCode(user.MfaSecretKey, model.VerificationCode))
            {
                ModelState.AddModelError("VerificationCode", "Invalid verification code. Please try again.");
                return View(model);
            }

            // Enable MFA for user
            user.IsMfaEnabled = true;
            await _context.SaveChangesAsync();

            // Clear pending setup session
            HttpContext.Session.Remove("PendingMfaSetup");

            // If this was during registration, redirect to login
            if (pendingUserId != null)
            {
                TempData["SuccessMessage"] = "MFA enabled successfully! Please log in.";
                return RedirectToAction("Login", "Account");
            }

            // If logged in user enabled MFA, redirect to dashboard
            TempData["SuccessMessage"] = "Two-Factor Authentication has been enabled.";
            return RedirectToAction("Dashboard", "Home");
        }

        // =========================================================================
        // MFA VERIFICATION (During Login)
        // =========================================================================

        /// <summary>
        /// Display MFA verification page during login.
        /// GET: /Mfa/Verify
        /// </summary>
        [HttpGet]
        public IActionResult Verify()
        {
            // Check for pending MFA verification
            var pendingUserId = HttpContext.Session.GetInt32("PendingMfaUserId");
            
            if (pendingUserId == null)
            {
                return RedirectToAction("Login", "Account");
            }

            return View(new MfaVerifyViewModel());
        }

        /// <summary>
        /// Process MFA verification during login.
        /// POST: /Mfa/Verify
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Verify(MfaVerifyViewModel model)
        {
            // Check for pending MFA verification
            var pendingUserId = HttpContext.Session.GetInt32("PendingMfaUserId");
            
            if (pendingUserId == null)
            {
                return RedirectToAction("Login", "Account");
            }

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _context.Users.FindAsync(pendingUserId);
            if (user == null || string.IsNullOrEmpty(user.MfaSecretKey))
            {
                HttpContext.Session.Remove("PendingMfaUserId");
                return RedirectToAction("Login", "Account");
            }

            // Verify TOTP code
            if (!_totpService.VerifyCode(user.MfaSecretKey, model.Code))
            {
                ModelState.AddModelError("Code", "Invalid authentication code. Please try again.");
                return View(model);
            }

            // Clear pending MFA session
            HttpContext.Session.Remove("PendingMfaUserId");

            // Complete login
            user.LastLoginAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();

            HttpContext.Session.SetInt32("UserId", user.Id);
            HttpContext.Session.SetString("Username", user.Username);

            return RedirectToAction("Dashboard", "Home");
        }

        // =========================================================================
        // DISABLE MFA
        // =========================================================================

        /// <summary>
        /// Disable MFA for current user.
        /// POST: /Mfa/Disable
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Disable()
        {
            var userId = HttpContext.Session.GetInt32("UserId");
            
            if (userId == null)
            {
                return RedirectToAction("Login", "Account");
            }

            var user = await _context.Users.FindAsync(userId);
            if (user == null)
            {
                return RedirectToAction("Login", "Account");
            }

            // Disable MFA
            user.IsMfaEnabled = false;
            user.MfaSecretKey = null;
            await _context.SaveChangesAsync();

            TempData["SuccessMessage"] = "Two-Factor Authentication has been disabled.";
            return RedirectToAction("Dashboard", "Home");
        }

        // =========================================================================
        // HELPER METHODS
        // =========================================================================

        /// <summary>
        /// Format secret key with spaces for easier manual entry.
        /// </summary>
        private static string FormatSecretKey(string secretKey)
        {
            // Add space every 4 characters for readability
            var formatted = "";
            for (int i = 0; i < secretKey.Length; i++)
            {
                if (i > 0 && i % 4 == 0)
                {
                    formatted += " ";
                }
                formatted += secretKey[i];
            }
            return formatted;
        }
    }
}


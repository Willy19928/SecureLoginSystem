/*
 * =============================================================================
 * Account Controller
 * =============================================================================
 * 
 * Handles user registration, login, and logout operations.
 * Implements comprehensive security measures.
 * 
 * Security Features:
 * - BCrypt password hashing
 * - Input validation and sanitization
 * - CSRF protection via AntiForgeryToken
 * - Account lockout after failed attempts
 * - Parameterized queries via Entity Framework
 * - XSS prevention through output encoding
 * =============================================================================
 */

using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SecureLoginSystem.Data;
using SecureLoginSystem.Models;
using SecureLoginSystem.Models.ViewModels;
using SecureLoginSystem.Services;
using System.Text.Encodings.Web;

namespace SecureLoginSystem.Controllers
{
    /// <summary>
    /// Controller for user authentication operations.
    /// </summary>
    public class AccountController : Controller
    {
        private readonly AppDbContext _context;
        private readonly IPasswordHasher _passwordHasher;
        private readonly ITotpService _totpService;

        // Account lockout configuration
        private const int MaxFailedAttempts = 5;
        private const int LockoutMinutes = 15;

        public AccountController(
            AppDbContext context,
            IPasswordHasher passwordHasher,
            ITotpService totpService)
        {
            _context = context;
            _passwordHasher = passwordHasher;
            _totpService = totpService;
        }

        // =========================================================================
        // REGISTRATION
        // =========================================================================

        /// <summary>
        /// Display registration form.
        /// GET: /Account/Register
        /// </summary>
        [HttpGet]
        public IActionResult Register()
        {
            // Redirect if already logged in
            if (HttpContext.Session.GetInt32("UserId") != null)
            {
                return RedirectToAction("Dashboard", "Home");
            }

            return View();
        }

        /// <summary>
        /// Process registration form submission.
        /// POST: /Account/Register
        /// 
        /// Security: ValidateAntiForgeryToken prevents CSRF attacks
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // Check if username already exists (case-insensitive)
            // Using Entity Framework parameterized query - SAFE from SQL Injection
            var existingUser = await _context.Users
                .FirstOrDefaultAsync(u => u.Username.ToLower() == model.Username.ToLower());

            if (existingUser != null)
            {
                ModelState.AddModelError("Username", "Username is already taken");
                return View(model);
            }

            // Check if email already exists
            var existingEmail = await _context.Users
                .FirstOrDefaultAsync(u => u.Email.ToLower() == model.Email.ToLower());

            if (existingEmail != null)
            {
                ModelState.AddModelError("Email", "Email is already registered");
                return View(model);
            }

            // Create new user with hashed password
            var user = new User
            {
                // Sanitize inputs by trimming whitespace
                Username = model.Username.Trim(),
                Email = model.Email.Trim().ToLower(),
                // Hash password using BCrypt - NEVER store plain text
                PasswordHash = _passwordHasher.HashPassword(model.Password),
                CreatedAt = DateTime.UtcNow,
                IsMfaEnabled = false
            };

            // Generate MFA secret if user opted in
            if (model.EnableMfa)
            {
                user.MfaSecretKey = _totpService.GenerateSecretKey();
            }

            // Save to database using Entity Framework
            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            // If MFA enabled, redirect to setup
            if (model.EnableMfa)
            {
                // Store pending MFA setup in session
                HttpContext.Session.SetInt32("PendingMfaSetup", user.Id);
                return RedirectToAction("SetupMfa", "Mfa");
            }

            // Success - redirect to login
            TempData["SuccessMessage"] = "Registration successful! Please log in.";
            return RedirectToAction("Login");
        }

        // =========================================================================
        // LOGIN
        // =========================================================================

        /// <summary>
        /// Display login form.
        /// GET: /Account/Login
        /// </summary>
        [HttpGet]
        public IActionResult Login()
        {
            // Redirect if already logged in
            if (HttpContext.Session.GetInt32("UserId") != null)
            {
                return RedirectToAction("Dashboard", "Home");
            }

            return View();
        }

        /// <summary>
        /// Process login form submission.
        /// POST: /Account/Login
        /// 
        /// Security measures:
        /// - CSRF protection via ValidateAntiForgeryToken
        /// - Account lockout after failed attempts
        /// - Timing-safe password comparison (BCrypt)
        /// - Generic error messages to prevent user enumeration
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // Find user by username (case-insensitive)
            // Entity Framework parameterized query - SAFE from SQL Injection
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Username.ToLower() == model.Username.ToLower());

            // Generic error message to prevent user enumeration attacks
            const string genericError = "Invalid username or password";

            if (user == null)
            {
                // User not found - use generic error
                ModelState.AddModelError("", genericError);
                return View(model);
            }

            // Check if account is locked out
            if (user.LockoutEnd != null && user.LockoutEnd > DateTime.UtcNow)
            {
                var remainingMinutes = (int)(user.LockoutEnd.Value - DateTime.UtcNow).TotalMinutes + 1;
                ModelState.AddModelError("", $"Account is locked. Try again in {remainingMinutes} minute(s).");
                return View(model);
            }

            // Verify password using BCrypt (timing-safe comparison)
            if (!_passwordHasher.VerifyPassword(model.Password, user.PasswordHash))
            {
                // Increment failed attempts
                user.FailedLoginAttempts++;

                // Lock account if max attempts exceeded
                if (user.FailedLoginAttempts >= MaxFailedAttempts)
                {
                    user.LockoutEnd = DateTime.UtcNow.AddMinutes(LockoutMinutes);
                    await _context.SaveChangesAsync();
                    ModelState.AddModelError("", $"Too many failed attempts. Account locked for {LockoutMinutes} minutes.");
                    return View(model);
                }

                await _context.SaveChangesAsync();
                ModelState.AddModelError("", genericError);
                return View(model);
            }

            // Password correct - reset failed attempts
            user.FailedLoginAttempts = 0;
            user.LockoutEnd = null;

            // Check if MFA is required
            if (user.IsMfaEnabled && !string.IsNullOrEmpty(user.MfaSecretKey))
            {
                // Store pending MFA verification
                HttpContext.Session.SetInt32("PendingMfaUserId", user.Id);
                await _context.SaveChangesAsync();
                return RedirectToAction("Verify", "Mfa");
            }

            // Complete login (no MFA)
            await CompleteLogin(user);
            return RedirectToAction("Dashboard", "Home");
        }

        /// <summary>
        /// Complete the login process and set session.
        /// </summary>
        internal async Task CompleteLogin(User user)
        {
            // Update last login timestamp
            user.LastLoginAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();

            // Set session variables
            HttpContext.Session.SetInt32("UserId", user.Id);
            HttpContext.Session.SetString("Username", user.Username);
        }

        // =========================================================================
        // LOGOUT
        // =========================================================================

        /// <summary>
        /// Log out the current user.
        /// POST: /Account/Logout
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Logout()
        {
            // Clear all session data
            HttpContext.Session.Clear();
            
            TempData["SuccessMessage"] = "You have been logged out successfully.";
            return RedirectToAction("Login");
        }

        /// <summary>
        /// GET logout (redirect to POST form).
        /// </summary>
        [HttpGet]
        public IActionResult Logout_Get()
        {
            return RedirectToAction("Dashboard", "Home");
        }
    }
}


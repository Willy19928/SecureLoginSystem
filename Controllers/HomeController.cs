/*
 * =============================================================================
 * Home Controller
 * =============================================================================
 * 
 * Handles main navigation and dashboard views.
 * Includes authentication checks for protected pages.
 * =============================================================================
 */

using Microsoft.AspNetCore.Mvc;
using SecureLoginSystem.Data;

namespace SecureLoginSystem.Controllers
{
    /// <summary>
    /// Controller for home and dashboard pages.
    /// </summary>
    public class HomeController : Controller
    {
        private readonly AppDbContext _context;

        public HomeController(AppDbContext context)
        {
            _context = context;
        }

        /// <summary>
        /// Landing page - redirects to dashboard if logged in.
        /// </summary>
        public IActionResult Index()
        {
            // Check if user is already logged in
            if (HttpContext.Session.GetInt32("UserId") != null)
            {
                return RedirectToAction("Dashboard");
            }
            
            return View();
        }

        /// <summary>
        /// Protected dashboard page - requires authentication.
        /// </summary>
        public IActionResult Dashboard()
        {
            // Get user ID from session
            var userId = HttpContext.Session.GetInt32("UserId");
            
            if (userId == null)
            {
                // Not authenticated - redirect to login
                return RedirectToAction("Login", "Account");
            }

            // Get user information for display
            var user = _context.Users.Find(userId);
            
            if (user == null)
            {
                // User not found - clear session and redirect
                HttpContext.Session.Clear();
                return RedirectToAction("Login", "Account");
            }

            // Pass user info to view
            ViewBag.Username = user.Username;
            ViewBag.Email = user.Email;
            ViewBag.IsMfaEnabled = user.IsMfaEnabled;
            ViewBag.LastLogin = user.LastLoginAt?.ToString("yyyy-MM-dd HH:mm:ss UTC") ?? "First login";
            ViewBag.AccountCreated = user.CreatedAt.ToString("yyyy-MM-dd HH:mm:ss UTC");

            return View();
        }

        /// <summary>
        /// Error page handler.
        /// </summary>
        public IActionResult Error()
        {
            return View();
        }
    }
}


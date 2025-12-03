/*
 * =============================================================================
 * Secure Login & User Authentication System
 * =============================================================================
 * 
 * This application demonstrates secure coding practices for user authentication,
 * including password hashing, MFA (Multi-Factor Authentication), and protection
 * against common vulnerabilities like SQL Injection and XSS.
 * 
 * Author: Student Project
 * Course: Software Security and Reverse Engineering
 * =============================================================================
 */

using Microsoft.EntityFrameworkCore;
using SecureLoginSystem.Data;
using SecureLoginSystem.Services;

var builder = WebApplication.CreateBuilder(args);

// =============================================================================
// Service Configuration
// =============================================================================

// Add MVC services with Razor Views
builder.Services.AddControllersWithViews();

// Configure SQLite database with Entity Framework Core
// Using parameterized queries to prevent SQL Injection
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

// Register custom services for dependency injection
builder.Services.AddScoped<IPasswordHasher, PasswordHasher>();  // BCrypt password hashing
builder.Services.AddScoped<ITotpService, TotpService>();        // TOTP for MFA

// Configure session for user authentication state
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);  // Session timeout
    options.Cookie.HttpOnly = true;                   // Prevent XSS access to session cookie
    options.Cookie.IsEssential = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
});

// Add HttpContextAccessor for accessing session in services
builder.Services.AddHttpContextAccessor();

// Configure Antiforgery for CSRF protection
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
});

var app = builder.Build();

// =============================================================================
// Database Initialization
// =============================================================================

// Ensure database is created on startup
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    context.Database.EnsureCreated();
}

// =============================================================================
// Middleware Pipeline Configuration
// =============================================================================

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();  // HTTP Strict Transport Security
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// Enable session middleware
app.UseSession();

app.UseAuthorization();

// =============================================================================
// Route Configuration
// =============================================================================

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Account}/{action=Login}/{id?}");

// Start the application
app.Run();


# 🔐 SecureAuth - Secure Login & User Authentication System

[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?style=flat-square&logo=dotnet)](https://dotnet.microsoft.com/)
[![SQLite](https://img.shields.io/badge/SQLite-003B57?style=flat-square&logo=sqlite)](https://www.sqlite.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

A modern, secure user authentication system built with ASP.NET Core 8.0, featuring multi-factor authentication, password hashing, and comprehensive protection against common web vulnerabilities.

## ✨ Features

### 🛡️ Security Features

| Feature | Description |
|---------|-------------|
| **BCrypt Password Hashing** | Industry-standard password hashing with automatic salting and configurable work factor |
| **Two-Factor Authentication** | TOTP-based MFA compatible with Google Authenticator, Microsoft Authenticator |
| **SQL Injection Protection** | Entity Framework Core with parameterized queries |
| **XSS Prevention** | Input validation and automatic output encoding |
| **CSRF Protection** | Anti-forgery tokens on all forms |
| **Account Lockout** | Automatic lockout after failed login attempts |
| **Session Security** | HttpOnly cookies with secure configuration |

### 🎨 User Experience

- Modern, responsive UI with custom color scheme
- Real-time password strength indicator
- QR code scanning for easy MFA setup
- Clear error messages and validation feedback

## 🚀 Quick Start

### Prerequisites

- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/SecureLoginSystem.git
   cd SecureLoginSystem
   ```

2. **Restore dependencies**
   ```bash
   dotnet restore
   ```

3. **Run the application**
   ```bash
   dotnet run
   ```

4. **Open in browser**
   ```
   https://localhost:5001
   ```

## 📁 Project Structure

```
SecureLoginSystem/
├── Controllers/
│   ├── HomeController.cs       # Landing page & dashboard
│   ├── AccountController.cs    # Registration & login
│   └── MfaController.cs        # Two-factor authentication
├── Models/
│   ├── User.cs                 # User entity
│   └── ViewModels/             # Form models
├── Services/
│   ├── PasswordHasher.cs       # BCrypt implementation
│   └── TotpService.cs          # TOTP/MFA implementation
├── Data/
│   └── AppDbContext.cs         # Entity Framework context
├── Views/
│   ├── Home/                   # Home & dashboard views
│   ├── Account/                # Login & register views
│   ├── Mfa/                    # MFA setup & verify views
│   └── Shared/                 # Layout & partials
└── wwwroot/
    └── css/site.css            # Custom styles
```

## 🔒 Security Implementation

### Password Hashing

```csharp
// BCrypt with work factor 12
public string HashPassword(string password)
{
    return BCrypt.Net.BCrypt.HashPassword(password, 12);
}
```

### Multi-Factor Authentication

```csharp
// TOTP verification with ±30 second tolerance
public bool VerifyCode(string secretKey, string code)
{
    var totp = new Totp(keyBytes, step: 30, totpSize: 6);
    return totp.VerifyTotp(code, out _, new VerificationWindow(1, 1));
}
```

### SQL Injection Prevention

```csharp
// Entity Framework parameterized query - SAFE
var user = await _context.Users
    .FirstOrDefaultAsync(u => u.Username.ToLower() == model.Username.ToLower());
```

## 🛠️ Configuration

### Database Connection

Edit `appsettings.json`:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Data Source=SecureLogin.db"
  }
}
```

### Security Settings

The following security measures are configured in `Program.cs`:

- Session timeout: 30 minutes
- Account lockout: 5 failed attempts, 15 minute lockout
- Password work factor: 12 (BCrypt iterations: 2^12)

## 📊 Testing

### SQL Injection Test

```
Username: admin' OR '1'='1
Result: ❌ Login failed (Protected)
```

### XSS Test

```
Username: <script>alert('xss')</script>
Result: ❌ Rejected by validation (Protected)
```

### CSRF Test

```
Cross-origin POST without token
Result: ❌ 400 Bad Request (Protected)
```

## 📝 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Landing page |
| GET | `/Account/Login` | Login form |
| POST | `/Account/Login` | Process login |
| GET | `/Account/Register` | Registration form |
| POST | `/Account/Register` | Process registration |
| POST | `/Account/Logout` | Logout user |
| GET | `/Home/Dashboard` | Protected dashboard |
| GET | `/Mfa/SetupMfa` | MFA setup with QR |
| POST | `/Mfa/SetupMfa` | Verify & enable MFA |
| GET | `/Mfa/Verify` | MFA verification page |
| POST | `/Mfa/Verify` | Verify MFA code |
| POST | `/Mfa/Disable` | Disable MFA |

## 📚 Technologies Used

- **ASP.NET Core 8.0** - Web framework
- **Entity Framework Core** - ORM with SQLite
- **BCrypt.Net** - Password hashing
- **OTP.NET** - TOTP implementation
- **QRCoder** - QR code generation
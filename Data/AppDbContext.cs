/*
 * =============================================================================
 * Application Database Context
 * =============================================================================
 * 
 * Entity Framework Core database context for the authentication system.
 * Uses SQLite for data persistence.
 * 
 * Security Features:
 * - Entity Framework provides parameterized queries (prevents SQL Injection)
 * - LINQ queries are automatically sanitized
 * - No raw SQL queries that could be vulnerable
 * =============================================================================
 */

using Microsoft.EntityFrameworkCore;
using SecureLoginSystem.Models;

namespace SecureLoginSystem.Data
{
    /// <summary>
    /// Database context for the secure login system.
    /// Manages User entities with Entity Framework Core.
    /// </summary>
    public class AppDbContext : DbContext
    {
        /// <summary>
        /// Constructor accepting DbContext options for dependency injection.
        /// </summary>
        /// <param name="options">Database context configuration options</param>
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }

        /// <summary>
        /// Users table - stores all registered user accounts.
        /// </summary>
        public DbSet<User> Users { get; set; }

        /// <summary>
        /// Configure entity relationships and constraints.
        /// </summary>
        /// <param name="modelBuilder">Model builder for entity configuration</param>
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Configure User entity
            modelBuilder.Entity<User>(entity =>
            {
                // Ensure username is unique
                entity.HasIndex(u => u.Username)
                    .IsUnique()
                    .HasDatabaseName("IX_Users_Username");

                // Ensure email is unique
                entity.HasIndex(u => u.Email)
                    .IsUnique()
                    .HasDatabaseName("IX_Users_Email");

                // Configure string length constraints
                entity.Property(u => u.Username)
                    .HasMaxLength(50)
                    .IsRequired();

                entity.Property(u => u.Email)
                    .HasMaxLength(100)
                    .IsRequired();

                entity.Property(u => u.PasswordHash)
                    .HasMaxLength(256)
                    .IsRequired();

                entity.Property(u => u.MfaSecretKey)
                    .HasMaxLength(128);
            });
        }
    }
}


using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Claims;
using System.Text;

using Microsoft.IdentityModel.Tokens;

using NzbDrone.Common.EnvironmentInfo;
using NzbDrone.Core.Authentication;

namespace Radarr.Http.Authentication
{
    public interface IRadarrServiceTokenService
    {
        string MintToken(string subject, RadarrRole role);

        ClaimsPrincipal ValidateToken(string token);

        SecurityKey SigningKey { get; }
    }

    public class RadarrServiceTokenService : IRadarrServiceTokenService
    {
        private const string Issuer = "radarr";
        private const string Audience = "radarr";
        private const int KeySizeBytes = 32;

        private readonly byte[] _key;
        private readonly SymmetricSecurityKey _signingKey;

        public RadarrServiceTokenService(IAppFolderInfo appFolderInfo)
        {
            if (appFolderInfo == null)
            {
                throw new ArgumentNullException(nameof(appFolderInfo));
            }

            var keyPath = Path.Combine(appFolderInfo.AppDataFolder, "service-token.key");
            _key = LoadOrCreateKey(keyPath);

            if (_key.Length < KeySizeBytes)
            {
                throw new InvalidOperationException("Service token signing key must be at least 256 bits (32 bytes).");
            }

            _signingKey = new SymmetricSecurityKey(_key);
        }

        public SecurityKey SigningKey => _signingKey;

        private static byte[] LoadOrCreateKey(string keyPath)
        {
            var directory = Path.GetDirectoryName(keyPath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            if (!File.Exists(keyPath))
            {
                var bytes = new byte[KeySizeBytes];
                using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
                {
                    rng.GetBytes(bytes);
                }

                File.WriteAllText(keyPath, Convert.ToBase64String(bytes));
                return bytes;
            }

            var content = File.ReadAllText(keyPath).Trim();

            try
            {
                return Convert.FromBase64String(content);
            }
            catch (FormatException)
            {
                return Encoding.UTF8.GetBytes(content);
            }
        }

        public string MintToken(string subject, RadarrRole role)
        {
            var handler = new JwtSecurityTokenHandler();
            var credentials = new SigningCredentials(new SymmetricSecurityKey(_key), SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: Issuer,
                audience: Audience,
                claims: new[]
                {
                    new Claim("sub", subject ?? string.Empty),
                    new Claim("role", role.ToString()),
                },
                notBefore: DateTime.UtcNow,
                expires: DateTime.UtcNow.AddMinutes(5),
                signingCredentials: credentials);

            return handler.WriteToken(token);
        }

        public ClaimsPrincipal ValidateToken(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                return null;
            }

            try
            {
                var handler = new JwtSecurityTokenHandler();
                handler.InboundClaimTypeMap.Clear();

                var parameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = Issuer,
                    ValidateAudience = true,
                    ValidAudience = Audience,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromMinutes(2),
                    IssuerSigningKey = new SymmetricSecurityKey(_key),
                };

                return handler.ValidateToken(token, parameters, out _);
            }
            catch
            {
                return null;
            }
        }
    }

    public static class RadarrRolePermissions
    {
        public static IReadOnlyList<string> ForRole(RadarrRole role)
        {
            switch (role)
            {
                case RadarrRole.ReadOnly:
                    return new[] { "UI.Read" };
                case RadarrRole.AddSearch:
                    return new[] { "UI.Read", "UI.Add" };
                case RadarrRole.Manage:
                    return new[] { "UI.Read", "UI.Add", "UI.Manage" };
                case RadarrRole.Admin:
                    return new[] { "UI.Read", "UI.Add", "UI.Manage", "UI.Admin" };
                default:
                    throw new ArgumentOutOfRangeException(nameof(role));
            }
        }
    }
}

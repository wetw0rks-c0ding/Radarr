using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

using NLog;

namespace Radarr.Http.Authentication
{
    public record AuthentikValidationResult(bool Success, string FailureReason, string Subject, string Username, List<string> Groups);

    public interface IAuthentikTokenValidationService
    {
        Task<AuthentikValidationResult> ValidateAsync(string token);
    }

    public class AuthentikTokenValidationService : IAuthentikTokenValidationService
    {
        public const string FallbackIssuer = "https://auth.piracyhub.win/application/o/arrstack/";

        public const string Issuer = FallbackIssuer;

        public const string RequiredAudienceSubstring = "arrstack";

        private static readonly Logger Logger = LogManager.GetLogger(nameof(AuthentikTokenValidationService));

        private readonly IConfigurationManager<OpenIdConnectConfiguration> _configurationManager;
        private readonly NzbDrone.Core.Configuration.IConfigFileProvider _configFileProvider;

        public AuthentikTokenValidationService(IConfigurationManager<OpenIdConnectConfiguration> configurationManager = null, NzbDrone.Core.Configuration.IConfigFileProvider configFileProvider = null)
        {
            _configFileProvider = configFileProvider;

            var issuer = GetIssuer();

            if (configurationManager == null)
            {
                var manager = new ConfigurationManager<OpenIdConnectConfiguration>(
                    issuer + ".well-known/openid-configuration",
                    new OpenIdConnectConfigurationRetriever())
                {
                    AutomaticRefreshInterval = TimeSpan.FromHours(24),
                    RefreshInterval = TimeSpan.FromHours(24),
                };

                _configurationManager = manager;
            }
            else
            {
                _configurationManager = configurationManager;
            }
        }

        private string GetIssuer()
        {
            var authority = _configFileProvider?.OidcAuthority;
            if (!string.IsNullOrWhiteSpace(authority))
            {
                return authority.TrimEnd('/') + "/";
            }

            return FallbackIssuer;
        }

        private string GetExpectedAudience()
        {
            var clientId = _configFileProvider?.OidcClientId;
            if (!string.IsNullOrWhiteSpace(clientId))
            {
                return clientId.Trim();
            }

            return null;
        }

        public async Task<AuthentikValidationResult> ValidateAsync(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                return new AuthentikValidationResult(false, "invalid_token", null, null, new List<string>());
            }

            var cleanedToken = token.Trim();
            if (cleanedToken.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                cleanedToken = cleanedToken.Substring(7).Trim();
            }

            var handler = new JwtSecurityTokenHandler();
            handler.InboundClaimTypeMap.Clear();

            for (var attempt = 0; attempt < 2; attempt++)
            {
                try
                {
                    var configuration = await _configurationManager.GetConfigurationAsync(CancellationToken.None).ConfigureAwait(false);

                    var signingKeys = new List<SecurityKey>();
                    if (configuration != null && configuration.SigningKeys != null)
                    {
                        signingKeys.AddRange(configuration.SigningKeys);
                    }

                    if (configuration != null && configuration.JsonWebKeySet != null)
                    {
                        try
                        {
                            signingKeys.AddRange(configuration.JsonWebKeySet.GetSigningKeys());
                        }
                        catch
                        {
                        }
                    }

                    var issuer = GetIssuer();
                    var expectedAudience = GetExpectedAudience();

                    if (_configFileProvider != null && string.IsNullOrWhiteSpace(_configFileProvider.OidcAuthority))
                    {
                        return new AuthentikValidationResult(false, "invalid_token", null, null, new List<string>());
                    }

                    var parameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidIssuer = issuer,
                        ValidateAudience = true,
                        ValidAudience = expectedAudience,
                        AudienceValidator = expectedAudience != null
                            ? (audiences, securityToken, validationParameters) => audiences != null && audiences.Any(a => string.Equals(a, expectedAudience, StringComparison.Ordinal) ||
                                                                                                                                 string.Equals(a, "arrstack", StringComparison.OrdinalIgnoreCase))
                            : (audiences, securityToken, validationParameters) => audiences != null && audiences.Any(audience => !string.IsNullOrWhiteSpace(audience) &&
                                                                                                                                 (audience.Contains("arrstack", StringComparison.OrdinalIgnoreCase) ||
                                                                                                                                  audience.Contains(RequiredAudienceSubstring, StringComparison.OrdinalIgnoreCase) ||
                                                                                                                                  audience.Contains("sonarr", StringComparison.OrdinalIgnoreCase) ||
                                                                                                                                  audience.Contains("radarr", StringComparison.OrdinalIgnoreCase) ||
                                                                                                                                  audience.Contains("lidarr", StringComparison.OrdinalIgnoreCase) ||
                                                                                                                                  audience.Contains("prowlarr", StringComparison.OrdinalIgnoreCase))),
                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.FromMinutes(2),
                        IssuerSigningKeys = signingKeys.Count > 0 ? signingKeys : null,
                        ValidateIssuerSigningKey = signingKeys.Count > 0,
                    };

                    var principal = handler.ValidateToken(cleanedToken, parameters, out _);

                    var subject = principal?.FindFirst("sub")?.Value ?? principal?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
                    var username = principal?.FindFirst("preferred_username")?.Value ?? principal?.FindFirst("name")?.Value ?? principal?.FindFirst("email")?.Value ?? subject;

                    var groupsClaimName = _configFileProvider?.OidcGroupsClaim ?? "groups";
                    var groups = new List<string>();
                    var groupsClaim = principal?.FindFirst(groupsClaimName);
                    if (groupsClaim != null && !string.IsNullOrWhiteSpace(groupsClaim.Value))
                    {
                        var value = groupsClaim.Value;
                        if (value.Trim().StartsWith('['))
                        {
                            try
                            {
                                var parsed = System.Text.Json.JsonSerializer.Deserialize<List<string>>(value);
                                if (parsed != null)
                                {
                                    groups.AddRange(parsed.Where(g => !string.IsNullOrWhiteSpace(g)));
                                }
                            }
                            catch
                            {
                            }
                        }
                        else if (value.Contains(','))
                        {
                            groups.AddRange(value.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
                        }
                        else
                        {
                            groups.Add(value.Trim());
                        }
                    }

                    if (string.IsNullOrWhiteSpace(subject))
                    {
                        return new AuthentikValidationResult(false, "invalid_token", null, null, groups);
                    }

                    return new AuthentikValidationResult(true, null, subject, username, groups);
                }
                catch (Exception ex)
                {
                    if (attempt == 1)
                    {
                        Logger.Debug(ex, "Failed to validate Authentik token");
                        return new AuthentikValidationResult(false, "invalid_token", null, null, new List<string>());
                    }

                    _configurationManager.RequestRefresh();
                }
            }

            return new AuthentikValidationResult(false, "invalid_token", null, null, new List<string>());
        }
    }
}

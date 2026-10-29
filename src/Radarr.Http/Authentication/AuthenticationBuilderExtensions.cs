using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Security;
using System.Security.Claims;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Diacritical;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using NLog;
using NzbDrone.Common.Extensions;
using NzbDrone.Common.Http.Dispatchers;
using NzbDrone.Core.Authentication;
using NzbDrone.Core.Configuration;
using NzbDrone.Http.Authentication;

namespace Radarr.Http.Authentication
{
    public static class AuthenticationBuilderExtensions
    {
        private const string AuthorizedProperty = "radarr.authorized";

        private static readonly Logger Logger = LogManager.GetLogger(nameof(AuthenticationBuilderExtensions));

        private static readonly Regex CookieNameRegex =
            new Regex(@"[^a-z0-9]+", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Lock BackchannelHttpHandlerLock = new();

        private static SocketsHttpHandler _backchannelHttpHandler;

        public static AuthenticationBuilder AddAppAuthentication(this IServiceCollection services)
        {
            services.AddSingleton<IRadarrServiceTokenService, RadarrServiceTokenService>();
            services.AddSingleton<IAuthentikTokenValidationService, AuthentikTokenValidationService>();
            services.AddSingleton<IAuthorizationHandler, PermissionAuthorizationHandler>();

            services.AddAuthorization(options =>
            {
                options.AddPolicy("UI.Read", policy => policy.Requirements.Add(new PermissionRequirement(RadarrRole.ReadOnly)));
                options.AddPolicy("UI.Add", policy => policy.Requirements.Add(new PermissionRequirement(RadarrRole.AddSearch)));
                options.AddPolicy("UI.Manage", policy => policy.Requirements.Add(new PermissionRequirement(RadarrRole.Manage)));
                options.AddPolicy("UI.Admin", policy => policy.Requirements.Add(new PermissionRequirement(RadarrRole.Admin)));
                options.AddPolicy("UI", policy =>
                {
                    policy.RequireAuthenticatedUser();
                    policy.Requirements.Add(new BypassableDenyAnonymousAuthorizationRequirement());
                });
            });

            var builder = services.AddAuthentication(options =>
                {
                    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                })
                .AddNone(nameof(AuthenticationType.None))
                .AddExternal(nameof(AuthenticationType.External))
                .AddOidc(nameof(AuthenticationType.Oidc))
                .AddForms(nameof(AuthenticationType.Forms))
                .AddApiKey("API", options =>
                {
                    options.HeaderName = "X-Api-Key";
                    options.QueryName = "apikey";
                })
                .AddApiKey("SignalR", options =>
                {
                    options.HeaderName = "X-Api-Key";
                    options.QueryName = "access_token";
                });

            services.AddOptions<JwtBearerOptions>("Bearer")
                .Configure<IRadarrServiceTokenService>((options, tokenService) =>
                {
                    if (tokenService == null || tokenService.SigningKey == null)
                    {
                        return;
                    }

                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidIssuer = "radarr",
                        ValidateAudience = true,
                        ValidAudience = "radarr",
                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.FromMinutes(2),
                        IssuerSigningKey = tokenService.SigningKey,
                        NameClaimType = "sub",
                        RoleClaimType = "role"
                    };

                    options.Events = new JwtBearerEvents
                    {
                        OnTokenValidated = context =>
                        {
                            var principal = context.Principal;
                            if (principal == null)
                            {
                                return Task.CompletedTask;
                            }

                            var identity = principal.Identity as ClaimsIdentity;
                            if (identity == null)
                            {
                                identity = new ClaimsIdentity(principal.Claims, "Bearer");
                                context.Principal = new ClaimsPrincipal(identity);
                            }

                            if (principal.FindFirst("oidc_sub") == null)
                            {
                                var subClaim = principal.FindFirst("sub") ?? principal.FindFirst(ClaimTypes.NameIdentifier);
                                if (subClaim != null)
                                {
                                    identity.AddClaim(new Claim("oidc_sub", subClaim.Value));
                                }
                            }

                            if (principal.FindFirst("radarr_role") == null)
                            {
                                var roleClaim = principal.FindFirst("role") ?? principal.FindFirst(ClaimTypes.Role);
                                if (roleClaim != null)
                                {
                                    identity.AddClaim(new Claim("radarr_role", roleClaim.Value));
                                }
                            }

                            return Task.CompletedTask;
                        }
                    };
                });

            return builder.AddJwtBearer("Bearer", options => { });
        }

        private static AuthenticationBuilder AddApiKey(this AuthenticationBuilder authenticationBuilder, string name, Action<ApiKeyAuthenticationOptions> options)
        {
            return authenticationBuilder.AddScheme<ApiKeyAuthenticationOptions, ApiKeyAuthenticationHandler>(name,
                options);
        }

        private static AuthenticationBuilder AddNone(this AuthenticationBuilder authenticationBuilder, string name)
        {
            return authenticationBuilder.AddScheme<AuthenticationSchemeOptions, NoAuthenticationHandler>(name,
                options => { });
        }

        private static AuthenticationBuilder AddExternal(this AuthenticationBuilder authenticationBuilder, string name)
        {
            return authenticationBuilder.AddScheme<AuthenticationSchemeOptions, NoAuthenticationHandler>(name,
                options => { });
        }

        private static AuthenticationBuilder AddOidc(this AuthenticationBuilder authenticationBuilder, string name)
        {
            authenticationBuilder.Services.AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
                .Configure<IConfigFileProvider>((options, configFileProvider) =>
                {
                    var instanceName = GetCleanInstanceName(configFileProvider.InstanceName);

                    options.Cookie.Name = $"{instanceName}OIDC";
                    options.AccessDeniedPath = "/login?loginFailed=true";
                    options.LoginPath = "/login";
                    options.ReturnUrlParameter = "returnUrl";
                    options.ExpireTimeSpan = TimeSpan.FromDays(7);
                    options.SlidingExpiration = true;
                    options.Cookie.IsEssential = true;
                    options.Events.OnValidatePrincipal = async context =>
                    {
                        var configuredUser = configFileProvider.OidcUserIdentifier;

                        if (configFileProvider.EffectiveAuthenticationMethod() == AuthenticationType.Oidc)
                        {
                            if (context.Principal?.FindFirst("oidc_sub") != null)
                            {
                                return;
                            }

                            if (configuredUser.IsNotNullOrWhiteSpace() &&
                                string.Equals(context.Principal?.FindFirst("user")?.Value, configuredUser, StringComparison.OrdinalIgnoreCase))
                            {
                                return;
                            }
                        }
                        else if (configuredUser.IsNotNullOrWhiteSpace() &&
                                 string.Equals(context.Principal?.FindFirst("user")?.Value, configuredUser, StringComparison.OrdinalIgnoreCase))
                        {
                            return;
                        }

                        context.RejectPrincipal();
                        await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    };

                    options.Events.OnRedirectToLogin = context => EventOnRedirectCookiesLogin(context, 401);
                    options.Events.OnRedirectToAccessDenied = context => EventOnRedirectCookiesLogin(context, 403);
                });

            authenticationBuilder.Services.AddOptions<OpenIdConnectOptions>(name)
                .Configure<IConfigFileProvider, ICertificateValidationService>((options, configFileProvider, certificateValidationService) =>
                {
                    options.CorrelationCookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax;
                    options.NonceCookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax;

                    if (configFileProvider.AuthenticationMethod != AuthenticationType.Oidc ||
                        !configFileProvider.IsOidcConfigured())
                    {
                        options.Authority = "https://localhost";
                        options.ClientId = "Radarr";

                        return;
                    }

                    options.Authority = configFileProvider.OidcAuthority;
                    options.ClientId = configFileProvider.OidcClientId;
                    options.ClientSecret = configFileProvider.OidcClientSecret;
                    options.ResponseType = "code";
                    options.ResponseMode = "query";
                    options.UsePkce = true;
                    options.BackchannelHttpHandler = GetBackchannelHttpHandler(certificateValidationService);
                    options.Scope.Clear();

                    foreach (var scope in AuthenticationConfigurationExtensions.GetOidcScopes(configFileProvider.OidcScopes).Distinct(StringComparer.Ordinal))
                    {
                        options.Scope.Add(scope);
                    }

                    if (!options.Scope.Contains("offline_access"))
                    {
                        options.Scope.Add("offline_access");
                    }

                    options.MapInboundClaims = false;
                    options.GetClaimsFromUserInfoEndpoint = true;
                    options.SaveTokens = true;

                    options.Events.OnTicketReceived = context =>
                    {
                        var idToken = context.Properties?.GetTokenValue("id_token");

                        context.Properties?.StoreTokens(idToken.IsNullOrWhiteSpace()
                            ? Array.Empty<AuthenticationToken>()
                            : [new AuthenticationToken { Name = "id_token", Value = idToken }]);

                        if (context.Properties?.Items.ContainsKey(AuthorizedProperty) == true)
                        {
                            return Task.CompletedTask;
                        }

                        if (!TryAuthorizeWithGroups(configFileProvider, context.Principal, null))
                        {
                            context.HandleResponse();
                            context.Response.Redirect(configFileProvider.UrlBase + "/login?ssoFailed=true");
                            return Task.CompletedTask;
                        }

                        context.Properties.Items[AuthorizedProperty] = "true";

                        return Task.CompletedTask;
                    };

                    options.Events.OnRedirectToIdentityProviderForSignOut = context =>
                    {
                        if (context.ProtocolMessage.IssuerAddress.IsNullOrWhiteSpace())
                        {
                            Logger.Debug("The OIDC provider doesn't advertise an end session endpoint, signing out locally only");

                            context.HandleResponse();
                            context.Response.Redirect(configFileProvider.UrlBase + "/loggedout");
                        }

                        return Task.CompletedTask;
                    };

                    options.Events.OnRemoteFailure = context =>
                    {
                        Logger.Error(context.Failure, "OIDC authentication failed");

                        context.HandleResponse();
                        context.Response.Redirect(configFileProvider.UrlBase + "/login?ssoFailed=true");

                        return Task.CompletedTask;
                    };

                    // Custom event to validate only authorized users
                    options.Events.OnUserInformationReceived = context =>
                    {
                        if (!TryAuthorizeWithGroups(configFileProvider, context.Principal, context.User.RootElement))
                        {
                            context.Fail("User is not authorized to access this application");

                            return Task.CompletedTask;
                        }

                        context.Properties.Items[AuthorizedProperty] = "true";

                        return Task.CompletedTask;
                    };
                });

            return authenticationBuilder.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options => { })
                .AddOpenIdConnect(name, options => { });
        }

        private static SocketsHttpHandler GetBackchannelHttpHandler(ICertificateValidationService certificateValidationService)
        {
            lock (BackchannelHttpHandlerLock)
            {
                return _backchannelHttpHandler ??= new SocketsHttpHandler
                {
                    SslOptions = new SslClientAuthenticationOptions
                    {
                        RemoteCertificateValidationCallback = certificateValidationService.ShouldByPassValidationError
                    }
                };
            }
        }

        private static AuthenticationBuilder AddForms(this AuthenticationBuilder authenticationBuilder, string name)
        {
            authenticationBuilder.Services.AddOptions<CookieAuthenticationOptions>(nameof(AuthenticationType.Forms))
                .Configure<IConfigFileProvider>((options, configFileProvider) =>
                {
                    var instanceName = GetCleanInstanceName(configFileProvider.InstanceName);

                    options.Cookie.Name = $"{instanceName}Auth";
                    options.AccessDeniedPath = "/login?loginFailed=true";
                    options.LoginPath = "/login";
                    options.ExpireTimeSpan = TimeSpan.FromDays(7);
                    options.SlidingExpiration = true;
                    options.ReturnUrlParameter = "returnUrl";
                    options.Events.OnRedirectToLogin = context => EventOnRedirectCookiesLogin(context, 401);
                    options.Events.OnRedirectToAccessDenied = context => EventOnRedirectCookiesLogin(context, 403);
                });

            return authenticationBuilder.AddCookie(nameof(AuthenticationType.Forms));
        }

        private static bool TryAuthorizeWithGroups(IConfigFileProvider configFileProvider, ClaimsPrincipal principal, JsonElement? user)
        {
            var groupsClaimName = configFileProvider.OidcGroupsClaim ?? "groups";
            var groups = new List<string>();

            if (user.HasValue)
            {
                if (TryGetProperty(user.Value, groupsClaimName, out var groupsElement))
                {
                    ExtractGroups(groupsElement, groups);
                }
            }

            if (groups.Count == 0 && principal != null)
            {
                var claim = principal.FindFirst(groupsClaimName) ?? principal.FindFirst("groups") ?? principal.FindFirst("memberOf");
                if (claim != null && !string.IsNullOrWhiteSpace(claim.Value))
                {
                    var value = claim.Value;
                    if (value.Trim().StartsWith('['))
                    {
                        try
                        {
                            var parsed = JsonSerializer.Deserialize<List<string>>(value);
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
            }

            var role = OidcGroupMapping.Resolve(groups);
            if (role != null)
            {
                var claims = new List<Claim>
                {
                    new("AuthenticationType", nameof(AuthenticationType.Oidc)),
                    new("Provider", "OIDC"),
                    new("radarr_role", role.Value.ToString()),
                    new("oidc_sub", GetClaimValue(principal, user, "sub") ?? string.Empty)
                };

                if (!string.IsNullOrWhiteSpace(groupsClaimName))
                {
                    claims.Add(new Claim("oidc_groups", string.Join(",", groups)));
                }

                principal?.AddIdentity(new ClaimsIdentity(claims));

                return true;
            }

            var configuredUser = configFileProvider.OidcUserIdentifier;

            if (configuredUser.IsNullOrWhiteSpace())
            {
                Logger.Error("No authorized users configured");
                return false;
            }

            var identifiers = GetIdentifiers(principal, user);

            if (!identifiers.Any(i => string.Equals(i, configuredUser, StringComparison.OrdinalIgnoreCase)))
            {
                Logger.Error("User '{0}' is not authorized to access this application", identifiers.FirstOrDefault() ?? "unknown");
                return false;
            }

            var fallbackClaims = new List<Claim>
            {
                new("user", configuredUser),
                new("AuthenticationType", nameof(AuthenticationType.Oidc)),
                new("Provider", "OIDC"),
                new("radarr_role", RadarrRole.Admin.ToString()),
                new("oidc_sub", GetClaimValue(principal, user, "sub") ?? configuredUser)
            };

            principal?.AddIdentity(new ClaimsIdentity(fallbackClaims));

            return true;
        }

        private static void ExtractGroups(JsonElement element, List<string> groups)
        {
            if (element.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in element.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.String)
                    {
                        var value = item.GetString();
                        if (!string.IsNullOrWhiteSpace(value))
                        {
                            groups.Add(value);
                        }
                    }
                }

                return;
            }

            if (element.ValueKind == JsonValueKind.String)
            {
                var value = element.GetString();
                if (string.IsNullOrWhiteSpace(value))
                {
                    return;
                }

                if (value.Trim().StartsWith('['))
                {
                    try
                    {
                        var parsed = JsonSerializer.Deserialize<List<string>>(value);
                        if (parsed != null)
                        {
                            groups.AddRange(parsed.Where(g => !string.IsNullOrWhiteSpace(g)));
                        }
                    }
                    catch
                    {
                    }

                    return;
                }

                if (value.Contains(','))
                {
                    groups.AddRange(value.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
                    return;
                }

                groups.Add(value.Trim());
            }
        }

        private static bool TryGetProperty(JsonElement element, string propertyName, out JsonElement value)
        {
            if (element.ValueKind == JsonValueKind.Object && element.TryGetProperty(propertyName, out value))
            {
                return true;
            }

            value = default;
            return false;
        }

        private static bool TryAuthorize(IConfigFileProvider configFileProvider, ClaimsPrincipal principal, JsonElement? user)
        {
            var configuredUser = configFileProvider.OidcUserIdentifier;

            if (configuredUser.IsNullOrWhiteSpace())
            {
                Logger.Error("No authorized users configured");

                return false;
            }

            var identifiers = GetIdentifiers(principal, user);

            if (!identifiers.Any(i => string.Equals(i, configuredUser, StringComparison.OrdinalIgnoreCase)))
            {
                Logger.Error("User '{0}' is not authorized to access this application", identifiers.FirstOrDefault() ?? "unknown");

                return false;
            }

            var claims = new List<Claim>
            {
                new("user", configuredUser),
                new("AuthenticationType", nameof(AuthenticationType.Oidc)),
                new("Provider", "OIDC")
            };

            principal?.AddIdentity(new ClaimsIdentity(claims));

            return true;
        }

        private static List<string> GetIdentifiers(ClaimsPrincipal principal, JsonElement? user)
        {
            var identifiers = new List<string>();

            AddVerifiedEmail(identifiers, principal, user);

            var subject = GetClaimValue(principal, user, "sub");

            if (subject.IsNotNullOrWhiteSpace())
            {
                identifiers.Add(subject);
            }

            return identifiers;
        }

        private static void AddVerifiedEmail(List<string> identifiers, ClaimsPrincipal principal, JsonElement? user)
        {
            if (user.HasValue && TryGetString(user.Value, "email", out var userInfoEmail))
            {
                if (IsEmailVerified(user.Value))
                {
                    identifiers.Add(userInfoEmail);
                }

                return;
            }

            var email = principal?.FindFirst("email")?.Value;

            if (email.IsNotNullOrWhiteSpace() &&
                bool.TryParse(principal?.FindFirst("email_verified")?.Value, out var verified) &&
                verified)
            {
                identifiers.Add(email);
            }
        }

        private static string GetClaimValue(ClaimsPrincipal principal, JsonElement? user, string claim)
        {
            if (user.HasValue && TryGetString(user.Value, claim, out var value))
            {
                return value;
            }

            return principal?.FindFirst(claim)?.Value;
        }

        private static bool TryGetString(JsonElement element, string property, out string value)
        {
            if (element.TryGetProperty(property, out var jsonValue) && jsonValue.ValueKind == JsonValueKind.String)
            {
                value = jsonValue.GetString();

                return true;
            }

            value = null;

            return false;
        }

        private static bool IsEmailVerified(JsonElement user)
        {
            if (!user.TryGetProperty("email_verified", out var value))
            {
                return false;
            }

            return value.ValueKind switch
            {
                JsonValueKind.True => true,
                JsonValueKind.String => bool.TryParse(value.GetString(), out var parsed) && parsed,
                _ => false
            };
        }

        private static string GetCleanInstanceName(string instanceName)
        {
            // Replace diacritics and replace non-word characters to ensure cookie name doesn't contain any valid URL characters not allowed in cookie names
            instanceName = instanceName.RemoveDiacritics();
            instanceName = CookieNameRegex.Replace(instanceName, string.Empty);

            return instanceName;
        }

        private static Task EventOnRedirectCookiesLogin(RedirectContext<CookieAuthenticationOptions> context, int statusCode)
        {
            if (string.Equals(context.Request.Query[HeaderNames.XRequestedWith], "XMLHttpRequest", StringComparison.Ordinal) ||
                string.Equals(context.Request.Headers.XRequestedWith, "XMLHttpRequest", StringComparison.Ordinal))
            {
                context.Response.Headers.Location = context.RedirectUri;
                context.Response.StatusCode = statusCode;
            }
            else
            {
                context.Response.Redirect(context.RedirectUri);
            }

            return Task.CompletedTask;
        }
    }
}

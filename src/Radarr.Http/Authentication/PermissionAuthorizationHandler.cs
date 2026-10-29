using System;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authorization;

using NzbDrone.Core.Authentication;

namespace Radarr.Http.Authentication
{
    public class PermissionAuthorizationHandler : AuthorizationHandler<PermissionRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionRequirement requirement)
        {
            var hasOidcSub = context.User?.FindFirst("oidc_sub") != null;

            if (!hasOidcSub)
            {
                if (context.User?.Identity?.IsAuthenticated != true)
                {
                    return Task.CompletedTask;
                }

                var roleClaim = context.User?.FindFirst("role")?.Value
                    ?? context.User?.FindFirst("radarr_role")?.Value;
                if (roleClaim == null)
                {
                    context.Succeed(requirement);
                    return Task.CompletedTask;
                }

                var role = RadarrRole.Admin;
                if (Enum.TryParse<RadarrRole>(roleClaim, true, out var parsedRole) && Enum.IsDefined(typeof(RadarrRole), parsedRole))
                {
                    role = parsedRole;
                }

                if (role >= requirement.Minimum)
                {
                    context.Succeed(requirement);
                }

                return Task.CompletedTask;
            }

            var radarrRoleClaim = context.User?.FindFirst("radarr_role")?.Value;
            if (string.IsNullOrWhiteSpace(radarrRoleClaim) ||
                !Enum.TryParse<RadarrRole>(radarrRoleClaim, true, out var oidcRole) ||
                !Enum.IsDefined(typeof(RadarrRole), oidcRole))
            {
                return Task.CompletedTask;
            }

            if (oidcRole >= requirement.Minimum)
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }
}

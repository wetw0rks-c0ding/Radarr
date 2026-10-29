using Microsoft.AspNetCore.Authorization;

using NzbDrone.Core.Authentication;

namespace Radarr.Http.Authentication
{
    public class PermissionRequirement : IAuthorizationRequirement
    {
        public RadarrRole Minimum { get; }

        public PermissionRequirement(RadarrRole minimum)
        {
            Minimum = minimum;
        }
    }
}

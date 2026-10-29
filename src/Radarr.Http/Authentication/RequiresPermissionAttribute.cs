using System;

using Microsoft.AspNetCore.Authorization;

using NzbDrone.Core.Authentication;

namespace Radarr.Http.Authentication
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false)]
    public class RequiresPermissionAttribute : AuthorizeAttribute
    {
        public RequiresPermissionAttribute(RadarrRole role)
        {
            Policy = role switch
            {
                RadarrRole.ReadOnly => "UI.Read",
                RadarrRole.AddSearch => "UI.Add",
                RadarrRole.Manage => "UI.Manage",
                RadarrRole.Admin => "UI.Admin",
                _ => throw new ArgumentOutOfRangeException(nameof(role), role, null)
            };
        }
    }
}

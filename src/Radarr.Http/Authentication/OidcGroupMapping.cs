using System;
using System.Collections.Generic;

using NzbDrone.Core.Authentication;

namespace Radarr.Http.Authentication
{
    public static class OidcGroupMapping
    {
        public static readonly Dictionary<string, string> GroupToTier = new(StringComparer.OrdinalIgnoreCase)
        {
            ["pirates"] = "T1",
            ["homies"] = "T2",
            ["family"] = "T3",
            ["maintenance"] = "T4",
            ["authentik Admins"] = "T5",
        };

        private static readonly Dictionary<string, RadarrRole> TierToRole = new(StringComparer.OrdinalIgnoreCase)
        {
            ["T2"] = RadarrRole.ReadOnly,
            ["T3"] = RadarrRole.AddSearch,
            ["T4"] = RadarrRole.Manage,
            ["T5"] = RadarrRole.Admin,
        };

        public static RadarrRole? Resolve(IEnumerable<string> groups)
        {
            if (groups == null)
            {
                return null;
            }

            RadarrRole? best = null;

            foreach (var group in groups)
            {
                if (string.IsNullOrWhiteSpace(group))
                {
                    continue;
                }

                if (!GroupToTier.TryGetValue(group, out var tier))
                {
                    continue;
                }

                if (!TierToRole.TryGetValue(tier, out var role))
                {
                    continue;
                }

                if (best == null || role > best.Value)
                {
                    best = role;
                }
            }

            return best;
        }
    }
}

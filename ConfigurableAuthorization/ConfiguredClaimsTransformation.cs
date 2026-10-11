using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace ConfigurableAuthorization;

public sealed class ConfiguredClaimsTransformation<TGrant>(
    IOptions<AuthorizationOptions<TGrant>> options, AuthorizationDefinition definition) : IClaimsTransformation
    where TGrant : PermissionGrantOptions
{
    public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        // Work on a clone and rebuild internal claims. Incoming app_* claims are never trusted.
        var user = new ClaimsPrincipal(principal.Identities.Select(identity => identity.Clone()));
        foreach (var identity in user.Identities)
            foreach (var claim in identity.Claims.Where(c => c.Type.StartsWith(definition.InternalClaimPrefix, StringComparison.Ordinal)).ToArray())
                identity.RemoveClaim(claim);

        if (!user.Identities.Any(identity => identity.IsAuthenticated) || IdentityClaims.Actor(user, definition) is not { } actor)
            return Task.FromResult(user);

        var settings = options.Value;
        var roles = new HashSet<string>(StringComparer.Ordinal);
        if (settings.ActorRoles.TryGetValue(actor, out var defaults)) roles.UnionWith(defaults);
        foreach (var mapping in settings.RoleMappings.Where(mapping => mapping.Actor == actor))
            if (IdentityClaims.Find(user, mapping.ClaimType).Any(claim => definition.SpaceSeparatedClaimTypes.Contains(mapping.ClaimType)
                ? claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries).Contains(mapping.Value, StringComparer.Ordinal)
                : claim.Value == mapping.Value))
                roles.Add(mapping.Role);

        // A separate identity gives IsInRole the same role claim type for all authentication schemes.
        var derived = new ClaimsIdentity("ApplicationRoles", ClaimTypes.Name, definition.RoleClaimType);
        foreach (var role in roles)
            derived.AddClaim(new Claim(definition.RoleClaimType, role));
        // Do not accumulate empty application identities across repeated transformations.
        var identities = user.Identities.Where(identity => identity.AuthenticationType != "ApplicationRoles").ToList();
        identities.Add(derived);
        return Task.FromResult(new ClaimsPrincipal(identities));
    }
}

using System.Security.Claims;
using Microsoft.Extensions.Options;

namespace ConfigurableAuthorization;

internal sealed class ConfiguredAccessResolver<TGrant, TAccess>(
    IOptions<AuthorizationOptions<TGrant>> options, AuthorizationDefinition definition,
    ConfiguredClaimsTransformation<TGrant> transformation, IGrantEvaluator<TGrant, TAccess> evaluator)
    : IAccessResolver<TAccess> where TGrant : PermissionGrantOptions where TAccess : class
{
    public async Task<IReadOnlyList<TAccess>> ResolveAsync(ClaimsPrincipal principal, string permission)
    {
        if (!definition.Permissions.Contains(permission)) return [];
        var user = await transformation.TransformAsync(principal);
        if (!user.Identities.Any(identity => identity.IsAuthenticated)
            || IdentityClaims.Actor(user, definition) is null) return [];

        var grants = new List<TAccess>();
        foreach (var role in IdentityClaims.Find(user, definition.RoleClaimType).Select(c => c.Value).Distinct())
        {
            if (!options.Value.Roles.TryGetValue(role, out var configuredRole)) continue;
            foreach (var grant in configuredRole.Grants.Where(g => g.Permissions.Contains(permission, StringComparer.Ordinal)))
                if (evaluator.Evaluate(user, grant) is { } access) grants.Add(access);
        }
        return grants.AsReadOnly();
    }
}

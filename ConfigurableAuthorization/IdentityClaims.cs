using System.Security.Claims;

namespace ConfigurableAuthorization;

public static class IdentityClaims
{
    public static IEnumerable<Claim> Find(ClaimsPrincipal user, string type) =>
        user.Identities.Where(identity => identity.IsAuthenticated).SelectMany(identity => identity.FindAll(type));

    public static Guid? ReadGuid(ClaimsPrincipal user, string type) =>
        Find(user, type).Select(claim => claim.Value).ToArray() is [var value]
            && Guid.TryParse(value, out var id) && id != Guid.Empty ? id : null;

    internal static string? Actor(ClaimsPrincipal user, AuthorizationDefinition definition)
    {
        var values = Find(user, definition.ActorClaimType).Select(claim => claim.Value).ToArray();
        var actor = values.Length == 0 ? definition.DefaultActor : values.Length == 1 ? values[0] : null;
        return actor is not null && definition.ActorTypes.Contains(actor) ? actor : null;
    }
}

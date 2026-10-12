using System.Security.Claims;
using ConfigurableAuthorization;

namespace Loans.Features.LoanApplications.Authorization;

// Grant and identity constraints shared by resource authorization and queries.
internal static class LoanGrantConditions
{
    internal static IEnumerable<string> Validate(LoanGrantOptions grant)
    {
        if (grant.Products is not null && grant.Products.Any(p => !LoanProducts.IsValidCode(p)))
            yield return "Invalid product.";
        if (grant.Channels is not null && grant.Channels.Any(c => !LoanChannels.IsValid(c)))
            yield return "Invalid channel.";
    }

    internal static bool IsEligible(ClaimsPrincipal user, LoanGrantOptions grant)
    {
        var products = Values(user, ApiSecurity.AllowedProductClaim);
        var channels = Values(user, ApiSecurity.AllowedChannelClaim);
        return products.All(LoanProducts.IsValidCode) && channels.All(LoanChannels.IsValid)
            && Overlaps(grant.Products, products) && Overlaps(grant.Channels, channels)
            // Branch-origin grants cannot be used with digital/store-only restrictions.
            && (grant.Scope != "OwnBranch" || Allows(grant.Channels, channels, LoanChannels.Branch));
    }

    internal static LoanAccess? Constrain(ClaimsPrincipal user, LoanGrantOptions grant, LoanAccess access)
    {
        var result = access with
        {
            Products = Intersect(access.Products,
                Intersect(grant.Products, ClaimRestriction(user, ApiSecurity.AllowedProductClaim))),
            Channels = Intersect(access.Channels,
                Intersect(grant.Channels, ClaimRestriction(user, ApiSecurity.AllowedChannelClaim)))
        };
        return result.Products is { Length: 0 } || result.Channels is { Length: 0 } ? null : result;
    }

    private static string[]? Intersect(string[]? left, string[]? right) =>
        left is null ? right : right is null ? left : left.Intersect(right, StringComparer.Ordinal).ToArray();

    private static string[]? ClaimRestriction(ClaimsPrincipal user, string type) =>
        Values(user, type) is { Length: > 0 } values ? values : null;

    private static string[] Values(ClaimsPrincipal user, string type) =>
        IdentityClaims.Find(user, type).Select(c => c.Value).Distinct(StringComparer.Ordinal).ToArray();

    private static bool Overlaps(string[]? configured, string[] claims) =>
        configured is null || configured.Any(value => claims.Length == 0 || claims.Contains(value, StringComparer.Ordinal));

    private static bool Allows(string[]? configured, string[] claims, string? value) =>
        (configured is null || (value is not null && configured.Contains(value, StringComparer.Ordinal)))
        && (claims.Length == 0 || (value is not null && claims.Contains(value, StringComparer.Ordinal)));
}

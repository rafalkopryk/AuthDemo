using System.Security.Claims;
using ConfigurableAuthorization;

namespace Loans.Features.LoanApplications.Authorization;

// Domain constraints only. Owner and branch access are enforced by the package's resource scopes.
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

    internal static LoanReadRestriction Restrictions(ClaimsPrincipal user, LoanGrantOptions grant) => new(
        Products: Intersect(grant.Products, ClaimRestriction(user, ApiSecurity.AllowedProductClaim)),
        Channels: Intersect(grant.Channels, ClaimRestriction(user, ApiSecurity.AllowedChannelClaim)));

    internal static bool Allows(ClaimsPrincipal user, LoanGrantOptions grant, string? product, string? channel)
    {
        var restriction = Restrictions(user, grant);
        return Contains(restriction.Products, product) && Contains(restriction.Channels, channel);
    }

    internal static string[]? Intersect(string[]? left, string[]? right) =>
        left is null ? right : right is null ? left : left.Intersect(right, StringComparer.Ordinal).ToArray();

    private static string[]? ClaimRestriction(ClaimsPrincipal user, string type) =>
        Values(user, type) is { Length: > 0 } values ? values : null;

    private static bool Contains(string[]? allowed, string? value) =>
        allowed is null || (value is not null && allowed.Contains(value, StringComparer.Ordinal));

    private static string[] Values(ClaimsPrincipal user, string type) =>
        IdentityClaims.Find(user, type).Select(c => c.Value).Distinct(StringComparer.Ordinal).ToArray();

    private static bool Overlaps(string[]? configured, string[] claims) =>
        configured is null || configured.Any(value => claims.Length == 0 || claims.Contains(value, StringComparer.Ordinal));

    private static bool Allows(string[]? configured, string[] claims, string? value) =>
        (configured is null || (value is not null && configured.Contains(value, StringComparer.Ordinal)))
        && (claims.Length == 0 || (value is not null && claims.Contains(value, StringComparer.Ordinal)));
}

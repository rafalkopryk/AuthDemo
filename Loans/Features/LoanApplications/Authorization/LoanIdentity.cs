using System.Security.Claims;

namespace Loans.Features.LoanApplications.Authorization;

internal static class LoanIdentity
{
    private static string[] TokenTypes(ClaimsPrincipal user) =>
        user.FindAll(ApiSecurity.TokenTypeClaim).Select(claim => claim.Value).ToArray();

    internal static string? Actor(ClaimsPrincipal user) => TokenTypes(user) switch
    {
        [] => "client",
        ["client"] => "client",
        ["technical"] => "technical",
        _ => null
    };

    internal static bool IsClient(ClaimsPrincipal user) => Actor(user) == "client";

    internal static Guid? ClientId(ClaimsPrincipal user) =>
        user.FindAll(ApiSecurity.ClientIdClaim).Select(claim => claim.Value).ToArray() is [var value]
            && Guid.TryParse(value, out var id) && id != Guid.Empty ? id : null;

}

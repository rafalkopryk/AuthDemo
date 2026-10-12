using System.Security.Claims;
using ConfigurableAuthorization;

namespace Loans.Features.LoanApplications.Authorization;

// Null means unrestricted; an empty array means no access. All fields belong to one grant.
internal sealed record LoanReadRestriction(Guid? ClientId = null, Guid? BranchId = null,
    string[]? Products = null, string[]? Channels = null);

/// <summary>Optional read support for a resource scope. Return null when access cannot be resolved.</summary>
internal interface ILoanReadScope
{
    string Name { get; }
    ValueTask<LoanReadRestriction?> ResolveAsync(ClaimsPrincipal user, CancellationToken cancellationToken);
}

internal sealed class AllLoanReadScope : ILoanReadScope
{
    public string Name => "All";
    public ValueTask<LoanReadRestriction?> ResolveAsync(ClaimsPrincipal user, CancellationToken cancellationToken) =>
        ValueTask.FromResult<LoanReadRestriction?>(new());
}

internal sealed class OwnLoanReadScope : ILoanReadScope
{
    public string Name => "Own";
    public ValueTask<LoanReadRestriction?> ResolveAsync(ClaimsPrincipal user, CancellationToken cancellationToken) =>
        ValueTask.FromResult<LoanReadRestriction?>(IdentityClaims.ReadGuid(user, ApiSecurity.ClientIdClaim) is { } id
            ? new(ClientId: id) : null);
}

internal sealed class BranchLoanReadScope(EmployeeBranchScope branchScope) : ILoanReadScope
{
    public string Name => "OwnBranch";
    public async ValueTask<LoanReadRestriction?> ResolveAsync(ClaimsPrincipal user, CancellationToken cancellationToken) =>
        await branchScope.ResolveBranchAsync(user, cancellationToken) is { } id
            ? new(BranchId: id, Channels: [LoanChannels.Branch]) : null;
}

internal sealed record AuthorizedLoanQuery(ListLoanApplicationsQuery Filters,
    IReadOnlyList<LoanReadRestriction> Alternatives);

internal sealed class LoanQueryAuthorization(IAccessResolver<ResourceGrant<LoanGrantOptions>> resolver,
    IEnumerable<ILoanReadScope> scopes)
{
    private readonly Dictionary<string, ILoanReadScope> scopesByName = scopes.ToDictionary(s => s.Name, StringComparer.Ordinal);

    // Only this service constructs the query accepted by the reader. No usable alternatives means forbidden.
    public async Task<AuthorizedLoanQuery?> AuthorizeAsync(ClaimsPrincipal user, ListLoanApplicationsQuery query,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var grants = await resolver.ResolveAsync(user, LoanPermissions.Read);
        var alternatives = new List<LoanReadRestriction>();
        foreach (var grant in grants)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!scopesByName.TryGetValue(grant.Options.Scope, out var scope)) continue;
            var access = await scope.ResolveAsync(grant.User, cancellationToken);
            if (access is null) continue;
            var conditions = LoanGrantConditions.Restrictions(grant.User, grant.Options);
            access = access with
            {
                Products = LoanGrantConditions.Intersect(access.Products, conditions.Products),
                Channels = LoanGrantConditions.Intersect(access.Channels, conditions.Channels)
            };
            if (access.Products is { Length: 0 } || access.Channels is { Length: 0 }) continue;
            if (query.ClientId is { } client && access.ClientId is { } owner && client != owner) continue;
            if (query.BranchId is { } branch && access.BranchId is { } allowedBranch && branch != allowedBranch) continue;
            if (query.Product is { } product && access.Products is { } products && !products.Contains(product)) continue;
            if (query.Channel is { } channel && access.Channels is { } channels && !channels.Contains(channel)) continue;
            alternatives.Add(access);
        }
        return alternatives.Count == 0 ? null : new(query, alternatives);
    }
}

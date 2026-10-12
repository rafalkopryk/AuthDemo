using System.Collections.Concurrent;
using System.Security.Claims;
using ConfigurableAuthorization;

namespace Loans.Features.LoanApplications.Authorization;

internal sealed class EmployeeBranchScope(IEnumerable<IEmployeeBranchResolver> resolvers)
    : IResourceScope<LoanApplicationResource>
{
    private const string EmployeeIdClaim = "employee_id";
    private readonly ConcurrentDictionary<string, Guid> branchCache = new(StringComparer.Ordinal);

    private static string? ReadEmployeeId(ClaimsPrincipal user) =>
        IdentityClaims.Find(user, EmployeeIdClaim).Select(claim => claim.Value).ToArray() is [var id]
            && !string.IsNullOrWhiteSpace(id) ? id : null;

    internal static bool CanEvaluate(ClaimsPrincipal user)
    {
        var branchClaims = IdentityClaims.Find(user, ApiSecurity.BranchIdClaim).ToArray();
        if (branchClaims.Length > 0) return IdentityClaims.ReadGuid(user, ApiSecurity.BranchIdClaim) is not null;
        return IdentityClaims.Find(user, ApiSecurity.TokenTypeClaim).Select(claim => claim.Value).ToArray()
                   is ["employee"]
               && ReadEmployeeId(user) is not null;
    }

    public async ValueTask<bool> AllowsAsync(ClaimsPrincipal user, LoanApplicationResource resource,
        CancellationToken cancellationToken)
    {
        if (resource.Channel != LoanChannels.Branch || resource.BranchId is null) return false;

        return await ResolveBranchAsync(user, cancellationToken) is { } branchId
            && resource.BranchId == branchId;
    }

    internal async ValueTask<Guid?> ResolveBranchAsync(ClaimsPrincipal user, CancellationToken cancellationToken)
    {
        var branchClaims = IdentityClaims.Find(user, ApiSecurity.BranchIdClaim).ToArray();
        if (branchClaims.Length > 0)
            return IdentityClaims.ReadGuid(user, ApiSecurity.BranchIdClaim);

        if (!CanEvaluate(user) || ReadEmployeeId(user) is not { } employeeId)
            return null;

        if (!branchCache.TryGetValue(employeeId, out var branchId))
        {
            var resolver = resolvers.SingleOrDefault();
            if (resolver is null) return null;
            branchId = await resolver.ResolveAsync(employeeId, cancellationToken) ?? Guid.Empty;
            branchCache.TryAdd(employeeId, branchId);
        }
        return branchId == Guid.Empty ? null : branchId;
    }
}

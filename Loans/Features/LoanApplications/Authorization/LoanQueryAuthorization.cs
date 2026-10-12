using System.Security.Claims;
using ConfigurableAuthorization;

namespace Loans.Features.LoanApplications.Authorization;

internal sealed record AuthorizedLoanQuery(ListLoanApplicationsQuery Filters,
    IReadOnlyList<LoanAccess> Alternatives);

internal sealed class LoanQueryAuthorization(ResourceAuthorization<LoanGrantOptions> authorization)
{
    public async Task<AuthorizedLoanQuery?> AuthorizeAsync(ClaimsPrincipal user, ListLoanApplicationsQuery query,
        CancellationToken cancellationToken)
    {
        var access = await authorization.ResolveAccessAsync<LoanApplicationResource, LoanAccess>(
            user, LoanPermissions.Read, cancellationToken);
        var alternatives = access.Where(a => a.Accepts(query)).ToArray();
        return alternatives.Length == 0 ? null : new(query, alternatives);
    }
}

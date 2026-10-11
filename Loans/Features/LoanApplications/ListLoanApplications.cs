using System.Security.Claims;
using ConfigurableAuthorization;
using Loans.Features.LoanApplications.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;

namespace Loans.Features.LoanApplications;

public sealed record ListLoanApplicationsQuery(int Skip = 0, int Take = 20);

internal sealed class ListLoanApplications(LoansDbContext dbContext, IAuthorizationService authorizationService,
    ResourceAuthorization<LoanGrantOptions> resourceAuthorization)
{
    public async Task<LoanApplicationResult<LoanApplication[]>> HandleAsync(
        ClaimsPrincipal user, ListLoanApplicationsQuery query, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var permission = await authorizationService.AuthorizeAsync(user, null,
            [new PermissionPresenceRequirement(LoanPermissions.Read)]);
        if (!permission.Succeeded) return new LoanForbidden();
        if (query.Skip < 0 || query.Take is < 1 or > 100)
            return new LoanInvalid(new()
            {
                ["pagination"] = ["Skip must be non-negative and take must be between 1 and 100."]
            });

        var candidates = await dbContext.LoanApplications.AsNoTracking()
            .OrderByDescending(item => item.CreatedAt).ThenBy(item => item.Id)
            .ToArrayAsync(cancellationToken);
        var visible = await resourceAuthorization.FilterAsync(user, candidates,
            loan => LoanApplicationResource.From(loan), LoanPermissions.Read, cancellationToken);
        // Page the authorized collection, never the unfiltered database result.
        return new LoanSuccess<LoanApplication[]>(
            visible.Skip(query.Skip).Take(query.Take).Select(application => application.ToModel()).ToArray());
    }
}

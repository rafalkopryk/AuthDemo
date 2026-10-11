using System.Security.Claims;
using ConfigurableAuthorization;
using Loans.Features.LoanApplications.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;

namespace Loans.Features.LoanApplications;

public sealed record GetLoanApplicationQuery(Guid Id);

internal sealed class GetLoanApplication(LoansDbContext dbContext, IAuthorizationService authorizationService)
{
    public async Task<LoanApplicationResult<LoanApplication>> HandleAsync(
        ClaimsPrincipal user, GetLoanApplicationQuery query, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var application = await dbContext.LoanApplications.AsNoTracking()
            .SingleOrDefaultAsync(item => item.Id == query.Id, cancellationToken);
        if (application is null) return new LoanNotFound();
        var authorization = await authorizationService.AuthorizeAsync(user, LoanApplicationResource.From(application),
            [new PermissionRequirement(LoanPermissions.Read)]);
        return authorization.Succeeded
            ? new LoanSuccess<LoanApplication>(application.ToModel())
            : new LoanForbidden();
    }
}

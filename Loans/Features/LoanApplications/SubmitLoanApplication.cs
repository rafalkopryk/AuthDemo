using System.Security.Claims;
using ConfigurableAuthorization;
using Loans.Features.LoanApplications.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;

namespace Loans.Features.LoanApplications;

public sealed record SubmitLoanApplicationCommand(Guid Id);

internal sealed class SubmitLoanApplication(LoansDbContext dbContext, IAuthorizationService authorizationService)
{
    public async Task<LoanApplicationMutationResult> HandleAsync(
        ClaimsPrincipal user, SubmitLoanApplicationCommand command, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var application = await dbContext.LoanApplications
            .SingleOrDefaultAsync(item => item.Id == command.Id, cancellationToken);
        if (application is null) return new LoanNotFound();

        var authorization = await authorizationService.AuthorizeAsync(user, LoanApplicationResource.From(application),
            [new PermissionRequirement(LoanPermissions.Submit)]);
        if (!authorization.Succeeded) return new LoanForbidden();

        if (application.Status != LoanApplicationStatus.Draft)
            return new LoanConflict("The application has already been submitted.");

        application.Status = LoanApplicationStatus.Submitted;
        application.SubmittedAt = DateTimeOffset.UtcNow;
        await dbContext.SaveChangesAsync(cancellationToken);
        return new LoanCompleted();
    }
}

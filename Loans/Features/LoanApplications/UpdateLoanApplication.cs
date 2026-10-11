using System.Security.Claims;
using ConfigurableAuthorization;
using Loans.Features.LoanApplications.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;

namespace Loans.Features.LoanApplications;

public sealed record UpdateLoanApplicationCommand(Guid Id, LoanApplicationRequest Application);

internal sealed class UpdateLoanApplication(LoansDbContext dbContext, IAuthorizationService authorizationService)
{
    public async Task<LoanApplicationMutationResult> HandleAsync(
        ClaimsPrincipal user, UpdateLoanApplicationCommand command, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var application = await dbContext.LoanApplications
            .SingleOrDefaultAsync(item => item.Id == command.Id, cancellationToken);
        if (application is null) return new LoanNotFound();
        var authorization = await authorizationService.AuthorizeAsync(user, LoanApplicationResource.From(application),
            [new PermissionRequirement(LoanPermissions.Edit)]);
        if (!authorization.Succeeded) return new LoanForbidden();
        var request = command.Application;
        var errors = request.Validate();
        if (errors.Count > 0)
            return new LoanInvalid(errors);

        if (application.Status != LoanApplicationStatus.Draft || application.ClientId != request.ClientId
            || application.Product != request.Product
            || (request.Channel is not null && application.Channel != request.Channel)
            || (request.BranchId is not null && application.BranchId != request.BranchId))
            return new LoanConflict("Only draft applications can be updated, and their client, product, channel and branch cannot be changed.");

        application.ApplicantName = request.ApplicantName.Trim();
        application.Amount = request.Amount;
        application.TermMonths = request.TermMonths;
        application.Purpose = request.Purpose;
        await dbContext.SaveChangesAsync(cancellationToken);
        return new LoanCompleted();
    }
}

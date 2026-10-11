using System.Security.Claims;
using ConfigurableAuthorization;
using Loans.Features.LoanApplications.Authorization;
using Microsoft.AspNetCore.Authorization;

namespace Loans.Features.LoanApplications;

public sealed record CreateLoanApplicationCommand(LoanApplicationRequest Application);

internal sealed class CreateLoanApplication(LoansDbContext dbContext, IAuthorizationService authorizationService)
{
    public async Task<LoanApplicationResult<LoanApplication>> HandleAsync(
        ClaimsPrincipal user, CreateLoanApplicationCommand command, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var request = command.Application;
        var errors = request.Validate(requireChannel: true);
        if (errors.Count > 0) return new LoanInvalid(errors);
        var authorization = await authorizationService.AuthorizeAsync(user, LoanApplicationResource.From(request),
            [new PermissionRequirement(LoanPermissions.Create)]);
        if (!authorization.Succeeded) return new LoanForbidden();

        var entity = new LoanApplicationEntity
        {
            Id = Guid.NewGuid(),
            ClientId = request.ClientId,
            ApplicantName = request.ApplicantName.Trim(),
            Amount = request.Amount,
            TermMonths = request.TermMonths,
            Purpose = request.Purpose,
            Product = request.Product,
            Channel = request.Channel,
            BranchId = request.BranchId,
            Status = LoanApplicationStatus.Draft,
            CreatedAt = DateTimeOffset.UtcNow
        };
        dbContext.LoanApplications.Add(entity);
        await dbContext.SaveChangesAsync(cancellationToken);
        return new LoanCreated<LoanApplication>(entity.ToModel(), entity.Id);
    }
}

namespace Loans.Features.LoanApplications.Authorization;

/// <summary>Immutable snapshot of the attributes used to authorize a loan application.</summary>
internal sealed record LoanApplicationResource(Guid ClientId, Guid? BranchId, string? Product, string? Channel)
{
    internal static LoanApplicationResource From(LoanApplicationEntity application) =>
        new(application.ClientId, application.BranchId, application.Product, application.Channel);

    internal static LoanApplicationResource From(LoanApplicationRequest request) =>
        new(request.ClientId, request.BranchId, request.Product, request.Channel);
}

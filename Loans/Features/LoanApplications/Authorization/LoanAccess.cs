using ConfigurableAuthorization;

namespace Loans.Features.LoanApplications.Authorization;

// Null fields mean unrestricted; empty arrays mean no access. All fields belong to one grant.
internal sealed record LoanAccess(Guid? ClientId = null, Guid? BranchId = null,
    string[]? Products = null, string[]? Channels = null) : IResourceAccess<LoanApplicationResource>
{
    public bool Allows(LoanApplicationResource resource) =>
        (ClientId is null || ClientId == resource.ClientId)
        && (BranchId is null || BranchId == resource.BranchId)
        && Contains(Products, resource.Product) && Contains(Channels, resource.Channel);

    internal bool Accepts(ListLoanApplicationsQuery query) =>
        (query.ClientId is null || ClientId is null || query.ClientId == ClientId)
        && (query.BranchId is null || BranchId is null || query.BranchId == BranchId)
        && (query.Product is null || Contains(Products, query.Product))
        && (query.Channel is null || Contains(Channels, query.Channel));

    private static bool Contains(string[]? allowed, string? value) =>
        allowed is null || (value is not null && allowed.Contains(value, StringComparer.Ordinal));
}

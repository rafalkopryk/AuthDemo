using System.Security.Claims;
using ConfigurableAuthorization;
using Loans.Features.LoanApplications.Authorization;
using Microsoft.AspNetCore.Authorization;

namespace Loans.Features.LoanApplications;

public sealed record ListLoanApplicationsQuery(int Skip = 0, int Take = 20, Guid? ClientId = null,
    string? Product = null, Guid? BranchId = null, string? Channel = null);

internal sealed class ListLoanApplications(LoanApplicationReader reader, IAuthorizationService authorizationService,
    LoanQueryAuthorization queryAuthorization)
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

        if (query.Product is { } product && !LoanProducts.IsValidCode(product))
            return new LoanInvalid(new() { ["product"] = ["Invalid product code."] });
        if (query.Channel is { } channel && !LoanChannels.IsValid(channel))
            return new LoanInvalid(new() { ["channel"] = ["Invalid channel."] });

        var authorized = await queryAuthorization.AuthorizeAsync(user, query, cancellationToken);
        if (authorized is null) return new LoanForbidden();
        return new LoanSuccess<LoanApplication[]>(await reader.SearchAsync(authorized, cancellationToken));
    }
}

using System.Security.Claims;
using LightAuthorization;
using Loans.Features.LoanApplications.Authorization;
using Microsoft.AspNetCore.Authorization;

namespace Loans.Features.LoanApplications;

public sealed record ListLoanApplicationsQuery(int Skip = 0, int Take = 20, Guid? ClientId = null,
    string? Product = null, Guid? BranchId = null, string? Channel = null);

internal sealed class ListLoanApplications(LoanApplicationReader reader, IAuthorizationService authorizationService,
    IAccessResolver<LoanApplicationResource, LoanAccess> accessResolver)
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

        var accesses = await accessResolver.ResolveAsync(user, LoanPermissions.Read, cancellationToken);
        if (accesses.Count == 0 || query.ClientId is { } requested && !accesses.Any(access => access.ClientId is null || access.ClientId == requested))
            return new LoanForbidden();

        return new LoanSuccess<LoanApplication[]>(await reader.SearchAsync(query, accesses, cancellationToken));
    }
}

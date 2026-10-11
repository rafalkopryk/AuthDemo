using System.Security.Claims;
using Loans.Features.LoanApplications;

namespace Loans;

public static class LoanApplicationEndpoints
{
    public static void MapLoanApplicationEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/loan-applications").WithTags("Loan applications")
            .RequireAuthorization();

        group.MapGet("/", async (ListLoanApplications handler, ClaimsPrincipal user,
            CancellationToken cancellationToken, int skip = 0, int take = 20) =>
        {
            return (await handler.HandleAsync(user, new ListLoanApplicationsQuery(skip, take), cancellationToken)).ToHttpResult();
        })
            .WithName("ListLoanApplications").RequireAuthorization(ApiSecurity.ReadPolicy);

        group.MapPost("/", async (LoanApplicationRequest request, CreateLoanApplication handler,
            ClaimsPrincipal user, CancellationToken cancellationToken) =>
        {
            return (await handler.HandleAsync(user, new CreateLoanApplicationCommand(request), cancellationToken)).ToHttpResult();
        })
            .WithName("CreateLoanApplication").RequireAuthorization(ApiSecurity.CreatePolicy);

        group.MapGet("/{id:guid}", async (Guid id, GetLoanApplication handler,
            ClaimsPrincipal user, CancellationToken cancellationToken) =>
        {
            return (await handler.HandleAsync(user, new GetLoanApplicationQuery(id), cancellationToken)).ToHttpResult();
        })
            .WithName("GetLoanApplication").RequireAuthorization(ApiSecurity.ReadPolicy);

        group.MapPut("/{id:guid}", async (Guid id, LoanApplicationRequest request,
            UpdateLoanApplication handler, ClaimsPrincipal user, CancellationToken cancellationToken) =>
        {
            return (await handler.HandleAsync(user, new UpdateLoanApplicationCommand(id, request), cancellationToken)).ToHttpResult();
        })
            .WithName("UpdateLoanApplication").RequireAuthorization(ApiSecurity.EditPolicy);

        group.MapPost("/{id:guid}/submit", async (Guid id, SubmitLoanApplication handler,
            ClaimsPrincipal user, CancellationToken cancellationToken) =>
        {
            return (await handler.HandleAsync(user, new SubmitLoanApplicationCommand(id), cancellationToken)).ToHttpResult();
        })
            .WithName("SubmitLoanApplication").RequireAuthorization(ApiSecurity.SubmitPolicy);
    }
}

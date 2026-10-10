namespace Loans;

public static class LoanApplicationEndpoints
{
    public static void MapLoanApplicationEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/loan-applications").WithTags("Loan applications");

        group.MapPost("/", async (LoanApplicationRequest request, LoanApplicationStore store, CancellationToken cancellationToken) =>
        {
            var errors = request.Validate();
            if (errors.Count > 0)
                return Results.ValidationProblem(errors);

            var application = await store.CreateAsync(request, cancellationToken);
            return Results.Created($"/loan-applications/{application.Id}", application);
        }).WithName("CreateLoanApplication");

        group.MapGet("/{id:guid}", async (Guid id, LoanApplicationStore store, CancellationToken cancellationToken) =>
            await store.GetAsync(id, cancellationToken) is { } application
                ? Results.Ok(application)
                : Results.NotFound())
            .WithName("GetLoanApplication");

        group.MapPut("/{id:guid}", async (Guid id, LoanApplicationRequest request, LoanApplicationStore store, CancellationToken cancellationToken) =>
        {
            var errors = request.Validate();
            if (errors.Count > 0)
                return Results.ValidationProblem(errors);

            var (application, conflict) = await store.UpdateAsync(id, request, cancellationToken);
            if (application is null)
                return Results.NotFound();

            return conflict
                ? Results.Problem(statusCode: StatusCodes.Status409Conflict,
                    detail: "Only draft applications can be updated.")
                : Results.Ok(application);
        }).WithName("UpdateLoanApplication");

        group.MapPost("/{id:guid}/submit", async (Guid id, LoanApplicationStore store, CancellationToken cancellationToken) =>
        {
            var (application, conflict) = await store.SubmitAsync(id, cancellationToken);
            if (application is null)
                return Results.NotFound();

            return conflict
                ? Results.Problem(statusCode: StatusCodes.Status409Conflict,
                    detail: "The application has already been submitted.")
                : Results.Ok(application);
        }).WithName("SubmitLoanApplication");
    }
}

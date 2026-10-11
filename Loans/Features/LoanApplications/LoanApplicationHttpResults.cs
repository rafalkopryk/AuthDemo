namespace Loans.Features.LoanApplications;

public static class LoanApplicationHttpResults
{
    public static IResult ToHttpResult(this LoanApplicationMutationResult result) => result switch
    {
        LoanCompleted => Results.NoContent(),
        LoanInvalid invalid => Results.ValidationProblem(invalid.Errors),
        LoanForbidden => Results.Forbid(),
        LoanNotFound => Results.NotFound(),
        LoanConflict conflict =>
            Results.Problem(statusCode: StatusCodes.Status409Conflict, detail: conflict.Detail),
        _ => throw new InvalidOperationException("Loan application result has no case.")
    };

    public static IResult ToHttpResult<T>(this LoanApplicationResult<T> result) => result switch
    {
        LoanSuccess<T> success => Results.Ok(success.Value),
        LoanCreated<T> created =>
            Results.Created($"/loan-applications/{created.Id}", created.Value),
        LoanInvalid invalid => Results.ValidationProblem(invalid.Errors),
        LoanForbidden => Results.Forbid(),
        LoanNotFound => Results.NotFound(),
        LoanConflict conflict =>
            Results.Problem(statusCode: StatusCodes.Status409Conflict, detail: conflict.Detail),
        _ => throw new InvalidOperationException("Loan application result has no case.")
    };
}

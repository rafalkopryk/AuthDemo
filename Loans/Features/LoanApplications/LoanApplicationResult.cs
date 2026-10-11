namespace Loans.Features.LoanApplications;

public sealed record LoanSuccess<T>(T Value);
public sealed record LoanCreated<T>(T Value, Guid Id);
public sealed record LoanInvalid(Dictionary<string, string[]> Errors);
public sealed record LoanForbidden;
public sealed record LoanNotFound;
public sealed record LoanConflict(string Detail);
public sealed record LoanCompleted;

public union LoanApplicationResult<T>(
    LoanSuccess<T>, LoanCreated<T>, LoanInvalid, LoanForbidden, LoanNotFound, LoanConflict);

public union LoanApplicationMutationResult(
    LoanCompleted, LoanInvalid, LoanForbidden, LoanNotFound, LoanConflict);

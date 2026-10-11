namespace Loans.Features.LoanApplications.Authorization;

/// <summary>Looks up an employee's branch when the validated token does not contain branch_id.</summary>
public interface IEmployeeBranchResolver
{
    Task<Guid?> ResolveAsync(string employeeId, CancellationToken cancellationToken);
}

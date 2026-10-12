using Microsoft.EntityFrameworkCore;
using Loans.Features.LoanApplications.Authorization;

namespace Loans.Features.LoanApplications;

internal sealed class LoanApplicationReader(LoansDbContext dbContext)
{
    public async Task<LoanApplication[]> SearchAsync(ListLoanApplicationsQuery filters, IReadOnlyList<LoanAccess> accesses,
        CancellationToken cancellationToken) =>
        (await BuildQuery(filters, accesses).ToArrayAsync(cancellationToken))
        .Select(item => item.ToModel()).ToArray();

    internal IQueryable<LoanApplicationEntity> BuildQuery(ListLoanApplicationsQuery filters, IReadOnlyList<LoanAccess> accesses)
    {
        var source = dbContext.LoanApplications.AsNoTracking();
        if (!accesses.Any(access => access.ClientId is null))
        {
            var clients = accesses.Select(access => access.ClientId!.Value).Distinct().ToArray();
            source = source.Where(loan => clients.Contains(loan.ClientId));
        }
        if (filters.ClientId is { } client) source = source.Where(loan => loan.ClientId == client);
        if (filters.BranchId is { } branch) source = source.Where(loan => loan.BranchId == branch);
        if (filters.Product is { } product) source = source.Where(loan => loan.Product == product);
        if (filters.Channel is { } channel) source = source.Where(loan => loan.Channel == channel);
        return source.OrderByDescending(loan => loan.CreatedAt).ThenBy(loan => loan.Id)
            .Skip(filters.Skip).Take(filters.Take);
    }
}

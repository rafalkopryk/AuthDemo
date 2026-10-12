using System.Linq.Expressions;
using Loans.Features.LoanApplications.Authorization;
using Microsoft.EntityFrameworkCore;

namespace Loans.Features.LoanApplications;

// Persistence-specific translation lives here; authorization returns only data constraints.
internal sealed class LoanApplicationReader(LoansDbContext dbContext)
{
    public async Task<LoanApplication[]> SearchAsync(AuthorizedLoanQuery query, CancellationToken cancellationToken) =>
        (await BuildQuery(query).ToArrayAsync(cancellationToken)).Select(item => item.ToModel()).ToArray();

    internal IQueryable<LoanApplicationEntity> BuildQuery(AuthorizedLoanQuery query)
    {
        var parameter = Expression.Parameter(typeof(LoanApplicationEntity), "loan");
        Expression allowed = Expression.Constant(false);
        foreach (var access in query.Alternatives)
        {
            Expression<Func<LoanApplicationEntity, bool>> clause = loan =>
                (!access.ClientId.HasValue || loan.ClientId == access.ClientId.Value)
                && (!access.BranchId.HasValue || loan.BranchId == access.BranchId.Value)
                && (access.Products == null || (loan.Product != null && access.Products.Contains(loan.Product)))
                && (access.Channels == null || (loan.Channel != null && access.Channels.Contains(loan.Channel)));
            allowed = Expression.OrElse(allowed, new ReplaceParameter(clause.Parameters[0], parameter).Visit(clause.Body));
        }
        var source = dbContext.LoanApplications.AsNoTracking()
            .Where(Expression.Lambda<Func<LoanApplicationEntity, bool>>(allowed, parameter));
        var filters = query.Filters;
        if (filters.ClientId is { } client) source = source.Where(loan => loan.ClientId == client);
        if (filters.BranchId is { } branch) source = source.Where(loan => loan.BranchId == branch);
        if (filters.Product is { } product) source = source.Where(loan => loan.Product == product);
        if (filters.Channel is { } channel) source = source.Where(loan => loan.Channel == channel);
        return source.OrderByDescending(loan => loan.CreatedAt).ThenBy(loan => loan.Id)
            .Skip(filters.Skip).Take(filters.Take);
    }

    private sealed class ReplaceParameter(ParameterExpression original, ParameterExpression replacement) : ExpressionVisitor
    {
        protected override Expression VisitParameter(ParameterExpression node) => node == original ? replacement : node;
    }
}

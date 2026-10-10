using Microsoft.EntityFrameworkCore;

namespace Loans;

public sealed class LoanApplicationStore(LoansDbContext dbContext)
{
    public async Task<LoanApplication> CreateAsync(
        LoanApplicationRequest request,
        CancellationToken cancellationToken)
    {
        var entity = new LoanApplicationEntity
        {
            Id = Guid.NewGuid(),
            ClientId = request.ClientId,
            ApplicantName = request.ApplicantName.Trim(),
            Amount = request.Amount,
            TermMonths = request.TermMonths,
            Purpose = request.Purpose,
            Status = LoanApplicationStatus.Draft,
            CreatedAt = DateTimeOffset.UtcNow
        };

        dbContext.LoanApplications.Add(entity);
        await dbContext.SaveChangesAsync(cancellationToken);
        return entity.ToModel();
    }

    public async Task<LoanApplication?> GetAsync(Guid id, CancellationToken cancellationToken)
    {
        var entity = await dbContext.LoanApplications
            .AsNoTracking()
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);

        return entity?.ToModel();
    }

    public async Task<(LoanApplication? Application, bool Conflict)> UpdateAsync(
        Guid id,
        LoanApplicationRequest request,
        CancellationToken cancellationToken)
    {
        var entity = await dbContext.LoanApplications
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);

        if (entity is null)
            return (null, false);

        if (entity.Status != LoanApplicationStatus.Draft)
            return (entity.ToModel(), true);

        entity.ClientId = request.ClientId;
        entity.ApplicantName = request.ApplicantName.Trim();
        entity.Amount = request.Amount;
        entity.TermMonths = request.TermMonths;
        entity.Purpose = request.Purpose;

        await dbContext.SaveChangesAsync(cancellationToken);
        return (entity.ToModel(), false);
    }

    public async Task<(LoanApplication? Application, bool Conflict)> SubmitAsync(
        Guid id,
        CancellationToken cancellationToken)
    {
        var entity = await dbContext.LoanApplications
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);

        if (entity is null)
            return (null, false);

        if (entity.Status != LoanApplicationStatus.Draft)
            return (entity.ToModel(), true);

        entity.Status = LoanApplicationStatus.Submitted;
        entity.SubmittedAt = DateTimeOffset.UtcNow;

        await dbContext.SaveChangesAsync(cancellationToken);
        return (entity.ToModel(), false);
    }
}

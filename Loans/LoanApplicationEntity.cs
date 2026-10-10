namespace Loans;

public sealed class LoanApplicationEntity
{
    public Guid Id { get; set; }
    public Guid ClientId { get; set; }
    public string ApplicantName { get; set; } = string.Empty;
    public decimal Amount { get; set; }
    public int TermMonths { get; set; }
    public string? Purpose { get; set; }
    public LoanApplicationStatus Status { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? SubmittedAt { get; set; }

    public LoanApplication ToModel() => new(
        Id, ClientId, ApplicantName, Amount, TermMonths, Purpose, Status, CreatedAt, SubmittedAt);
}

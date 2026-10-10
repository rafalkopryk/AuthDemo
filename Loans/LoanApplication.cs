namespace Loans;

public enum LoanApplicationStatus
{
    Draft,
    Submitted
}

public sealed record LoanApplication(
    Guid Id,
    Guid ClientId,
    string ApplicantName,
    decimal Amount,
    int TermMonths,
    string? Purpose,
    LoanApplicationStatus Status,
    DateTimeOffset CreatedAt,
    DateTimeOffset? SubmittedAt);

public sealed record LoanApplicationRequest(
    Guid ClientId,
    string ApplicantName,
    decimal Amount,
    int TermMonths,
    string? Purpose)
{
    public Dictionary<string, string[]> Validate()
    {
        var errors = new Dictionary<string, string[]>();

        if (ClientId == Guid.Empty)
            errors[nameof(ClientId)] = ["Client id is required and must not be empty."];

        if (string.IsNullOrWhiteSpace(ApplicantName))
            errors[nameof(ApplicantName)] = ["Applicant name is required."];

        if (Amount <= 0)
            errors[nameof(Amount)] = ["Amount must be greater than zero."];

        if (TermMonths <= 0)
            errors[nameof(TermMonths)] = ["Term in months must be greater than zero."];

        return errors;
    }
}

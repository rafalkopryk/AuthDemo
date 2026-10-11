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
    DateTimeOffset? SubmittedAt,
    string? Product = null,
    string? Channel = null,
    Guid? BranchId = null);

public sealed record LoanApplicationRequest(
    Guid ClientId,
    string ApplicantName,
    decimal Amount,
    int TermMonths,
    string? Purpose,
    string? Product = null,
    string? Channel = null,
    Guid? BranchId = null)
{
    public Dictionary<string, string[]> Validate(bool requireChannel = false)
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

        if (Product is not null && !LoanProducts.IsValidCode(Product))
            errors[nameof(Product)] = ["Product must be a lowercase product code of at most 64 characters (letters, digits and hyphens)."];

        if (requireChannel && Channel is null)
            errors[nameof(Channel)] = ["Channel is required when creating an application."];
        else if (Channel is not null && !LoanChannels.IsValid(Channel))
            errors[nameof(Channel)] = ["Channel must be branch, digital or store."];
        if (Channel == LoanChannels.Branch && (BranchId is null || BranchId == Guid.Empty))
            errors[nameof(BranchId)] = ["Branch channel requires a non-empty branch id."];
        if (Channel != LoanChannels.Branch && BranchId is not null)
            errors[nameof(BranchId)] = ["Branch id is only allowed for branch channel."];

        return errors;
    }
}

using ConfigurableAuthorization;

namespace Loans.Features.LoanApplications.Authorization;

public sealed class LoanGrantOptions : PermissionGrantOptions
{
    public string[]? Products { get; set; }
    public string[]? Channels { get; set; }
}

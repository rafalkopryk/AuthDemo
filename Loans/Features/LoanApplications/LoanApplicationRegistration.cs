namespace Loans.Features.LoanApplications;

public static class LoanApplicationRegistration
{
    public static IServiceCollection AddLoanApplicationOperations(this IServiceCollection services)
    {
        services.AddScoped<ListLoanApplications>();
        services.AddScoped<LoanApplicationReader>();
        services.AddScoped<GetLoanApplication>();
        services.AddScoped<CreateLoanApplication>();
        services.AddScoped<UpdateLoanApplication>();
        services.AddScoped<SubmitLoanApplication>();
        return services;
    }
}

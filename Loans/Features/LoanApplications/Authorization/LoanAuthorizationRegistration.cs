using ConfigurableAuthorization;

namespace Loans.Features.LoanApplications.Authorization;

internal static class LoanAuthorizationRegistration
{
    internal static void AddLoanAuthorization(this IServiceCollection services)
    {
        services.AddScoped<LoanQueryAuthorization>();
        services.AddScoped<ILoanReadScope, AllLoanReadScope>();
        services.AddScoped<ILoanReadScope, OwnLoanReadScope>();
        services.AddScoped<ILoanReadScope, BranchLoanReadScope>();
        services.AddCreditAuthroization<LoanGrantOptions>(options =>
        {
            options.Service("loans");
            options.Definition.ActorTypes.UnionWith(["client", "employee", "technical"]);
            options.Definition.ActorClaimType = ApiSecurity.TokenTypeClaim;
            options.Definition.DefaultActor = "client";
            options.Definition.RoleClaimType = ApiSecurity.ApplicationRoleClaim;
            options.ValidateWith(LoanGrantConditions.Validate);
            options.EvaluateWhen(LoanGrantConditions.IsEligible);

            options.Resource<LoanApplicationResource>()
                .Permissions(LoanPermissions.Read, LoanPermissions.Create, LoanPermissions.Edit, LoanPermissions.Submit)
                .AllowAll()
                .Own(resource => resource.ClientId, ApiSecurity.ClientIdClaim)
                .Scope<EmployeeBranchScope>("OwnBranch", EmployeeBranchScope.CanEvaluate)
                .Require((user, grant, resource) =>
                    LoanGrantConditions.Allows(user, grant, resource.Product, resource.Channel));
        });
    }
}

using ConfigurableAuthorization;

namespace Loans.Features.LoanApplications.Authorization;

internal static class LoanAuthorizationRegistration
{
    internal static void AddLoanAuthorization(this IServiceCollection services)
    {
        services.AddScoped<LoanQueryAuthorization>();
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
                .Access<LoanAccess>()
                .Scope("All", _ => new())
                .Scope("Own", user => IdentityClaims.ReadGuid(user, ApiSecurity.ClientIdClaim) is { } id
                    ? new(ClientId: id) : null,
                    eligible: user => IdentityClaims.ReadGuid(user, ApiSecurity.ClientIdClaim) is not null)
                .Scope<EmployeeBranchScope>("OwnBranch", EmployeeBranchScope.CanEvaluate)
                .Constrain(LoanGrantConditions.Constrain);
        });
    }
}

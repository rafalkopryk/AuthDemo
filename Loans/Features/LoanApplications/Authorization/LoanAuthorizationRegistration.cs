using LightAuthorization;

namespace Loans.Features.LoanApplications.Authorization;

internal static class LoanAuthorizationRegistration
{
    internal static void AddLoanAuthorization(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddLightAuthorization(options =>
        {
            options.MapRole("client", user => LoanIdentity.IsClient(user) && LoanIdentity.ClientId(user) is not null);
            options.MapRoleMappings(configuration.GetSection("Authorization:RoleMappings"), LoanIdentity.Actor);
            options.Roles(configuration.GetSection("Authorization:Roles"));

            options.Resource<LoanApplicationResource>().Access<LoanAccess>()
                .Map(access => access.ClientId, resource => resource.ClientId)
                .Scope("Own", user => LoanIdentity.ClientId(user) is { } id ? new LoanAccess(id) : null)
                .Scope("All", _ => new LoanAccess());
        });
    }
}

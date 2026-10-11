using Microsoft.Extensions.Configuration;

namespace ConfigurableAuthorization;

internal static class ServiceAuthorizationConfiguration
{
    // Bind only the selected service: other services may use entirely different grant schemas.
    internal static void Bind<TGrant>(IConfiguration section, string service, AuthorizationOptions<TGrant> options)
        where TGrant : PermissionGrantOptions
    {
        foreach (var child in section.GetChildren())
            if (child.Key is not ("ActorRoles" or "RoleMappings" or "Roles"))
                throw new InvalidOperationException($"Unknown authorization configuration field '{child.Key}'.");
        section.GetSection("ActorRoles").Bind(options.ActorRoles);
        options.RoleMappings = section.GetSection("RoleMappings").Get<RoleMappingOptions[]>(Strict) ?? [];
        foreach (var role in section.GetSection("Roles").GetChildren())
        {
            foreach (var child in role.GetChildren())
                if (child.Key != "Services")
                    throw new InvalidOperationException($"Role '{role.Key}' must contain only Services.");
            options.Roles[role.Key] = role.GetSection("Services").GetSection(service)
                .Get<RoleOptions<TGrant>>(Strict) ?? new();
        }
    }

    private static void Strict(BinderOptions options) => options.ErrorOnUnknownConfiguration = true;
}

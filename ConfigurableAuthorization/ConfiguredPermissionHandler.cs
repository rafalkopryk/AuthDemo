using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;

namespace ConfigurableAuthorization;

internal sealed class ConfiguredPermissionHandler<TAccess>(IAccessResolver<TAccess> resolver)
    : AuthorizationHandler<PermissionRequirement> where TAccess : class
{
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context, PermissionRequirement requirement)
    {
        var grants = await resolver.ResolveAsync(context.User, requirement.Permission);
        if (grants.Count == 0) return;
        switch (context.Resource)
        {
            case IAuthorizationResource<TAccess> resource when resource.Authorize(requirement.Permission, grants):
            case null: // Explicit permission-only check.
            case HttpContext: // Endpoint policy; the operation service checks the resource.
                context.Succeed(requirement);
                break;
        }
    }
}

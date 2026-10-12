using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;

namespace LightAuthorization;

internal sealed class PermissionPresenceHandler(LightAuthorizationDefinition definition)
    : AuthorizationHandler<PermissionPresenceRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
        PermissionPresenceRequirement requirement)
    {
        if (definition.Scopes(context.User, requirement.Permission).Any()) context.Succeed(requirement);
        return Task.CompletedTask;
    }
}

internal sealed class ResourcePermissionHandler<TResource, TAccess>(
    IAccessResolver<TResource, TAccess> resolver, AccessMapping<TResource, TAccess> mapping,
    IHttpContextAccessor httpContextAccessor)
    : AuthorizationHandler<ResourcePermissionRequirement, TResource>
    where TResource : class
    where TAccess : class
{
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context,
        ResourcePermissionRequirement requirement, TResource resource)
    {
        var accesses = await resolver.ResolveAsync(context.User, requirement.Permission,
            httpContextAccessor.HttpContext?.RequestAborted ?? CancellationToken.None);
        if (accesses.Any(access => mapping.Allows(access, resource))) context.Succeed(requirement);
    }
}

internal sealed class DirectResourcePermissionHandler<TResource>(
    LightAuthorizationDefinition definition, DirectScopeDefinition<TResource> scopes,
    IServiceProvider services, IHttpContextAccessor httpContextAccessor)
    : AuthorizationHandler<ResourcePermissionRequirement, TResource>
    where TResource : class
{
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context,
        ResourcePermissionRequirement requirement, TResource resource)
    {
        var token = httpContextAccessor.HttpContext?.RequestAborted ?? CancellationToken.None;
        foreach (var name in definition.Scopes(context.User, requirement.Permission).Distinct(StringComparer.Ordinal))
        {
            if (!scopes.TryGet(name, out var allows)) continue;
            token.ThrowIfCancellationRequested();
            if (!await allows!(services, context.User, resource, token)) continue;
            token.ThrowIfCancellationRequested();
            context.Succeed(requirement);
            return;
        }
    }
}

using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace ConfigurableAuthorization;

public sealed record ResourceGrant<TGrant>(ClaimsPrincipal User, TGrant Options) where TGrant : PermissionGrantOptions;

internal sealed class ResourceGrantEvaluator<TGrant>(ResourceAuthorizationBuilder<TGrant> definition)
    : IGrantEvaluator<TGrant, ResourceGrant<TGrant>> where TGrant : PermissionGrantOptions
{
    public IEnumerable<string> Validate(TGrant grant)
    {
        foreach (var permission in grant.Permissions)
        {
            var resources = definition.Resources.Where(pair => pair.Value.Permissions.Contains(permission)).ToArray();
            if (resources.Length == 0) yield return $"No resource supports permission '{permission}'.";
            foreach (var resource in resources)
                if (!resource.Value.Scopes.ContainsKey(grant.Scope))
                    yield return $"Resource '{resource.Key.Name}' does not support scope '{grant.Scope}' for '{permission}'.";
        }
        foreach (var error in definition.ValidateGrant(grant)) yield return error;
    }

    public ResourceGrant<TGrant>? Evaluate(ClaimsPrincipal user, TGrant grant) =>
        definition.Eligible(user, grant)
        && definition.Resources.Values.Any(resource => resource.Permissions.Overlaps(grant.Permissions)
            && resource.Scopes.TryGetValue(grant.Scope, out var scope) && scope.Eligible(user))
            ? new(user, grant) : null;
}

/// <summary>A preliminary endpoint check only. It does not authorize access to a resource.</summary>
public sealed record PermissionPresenceRequirement(string Permission) : IAuthorizationRequirement;

internal sealed class ResourcePermissionHandler<TGrant>(IAccessResolver<ResourceGrant<TGrant>> resolver,
    ResourceAuthorizationBuilder<TGrant> definition, IServiceProvider services) : IAuthorizationHandler
    where TGrant : PermissionGrantOptions
{
    public async Task HandleAsync(AuthorizationHandlerContext context)
    {
        var cancellationToken = services.GetRequiredService<IHttpContextAccessor>().HttpContext?.RequestAborted
                                ?? CancellationToken.None;
        foreach (var requirement in context.PendingRequirements.ToArray())
        {
            if (requirement is PermissionPresenceRequirement presence)
            {
                if ((await resolver.ResolveAsync(context.User, presence.Permission)).Count > 0)
                    context.Succeed(requirement);
            }
            else if (requirement is PermissionRequirement permission && context.Resource is { } resource
                && definition.Resources.TryGetValue(resource.GetType(), out var registration))
            {
                var grants = await resolver.ResolveAsync(context.User, permission.Permission);
                foreach (var grant in grants)
                    if (await registration.AllowsAsync(permission.Permission, resource, grant, services,
                            cancellationToken))
                    {
                        context.Succeed(requirement);
                        break;
                    }
            }
        }
    }
}

/// <summary>Optional filtering of an already loaded collection; no database dependency.</summary>
public sealed class ResourceAuthorization<TGrant>(IAccessResolver<ResourceGrant<TGrant>> resolver,
    ResourceAuthorizationBuilder<TGrant> definition, IServiceProvider services) where TGrant : PermissionGrantOptions
{
    public Task<TResource[]> FilterAsync<TResource>(ClaimsPrincipal user, IEnumerable<TResource> resources,
        string permission, CancellationToken cancellationToken = default) where TResource : class =>
        FilterAsync(user, resources, resource => resource, permission, cancellationToken);

    /// <summary>Filters items using dedicated authorization resources projected from each item.</summary>
    public async Task<TItem[]> FilterAsync<TItem, TResource>(ClaimsPrincipal user, IEnumerable<TItem> items,
        Func<TItem, TResource> resourceSelector, string permission, CancellationToken cancellationToken = default)
        where TResource : class
    {
        cancellationToken.ThrowIfCancellationRequested();
        var grants = await resolver.ResolveAsync(user, permission);
        var result = new List<TItem>();
        foreach (var item in items)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var resource = resourceSelector(item);
            if (resource is null || !definition.Resources.TryGetValue(resource.GetType(), out var registration))
                continue;
            foreach (var grant in grants)
                if (await registration.AllowsAsync(permission, resource, grant, services, cancellationToken))
                {
                    result.Add(item);
                    break;
                }
        }
        return result.ToArray();
    }
}

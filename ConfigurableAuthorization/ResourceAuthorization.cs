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

/// <summary>Resolves typed access for queries or filters already loaded items; no database dependency.</summary>
public sealed class ResourceAuthorization<TGrant>(IAccessResolver<ResourceGrant<TGrant>> resolver,
    ResourceAuthorizationBuilder<TGrant> definition, IServiceProvider services) where TGrant : PermissionGrantOptions
{
    /// <summary>Returns complete alternative grants. Apply AND within each access and OR between alternatives.</summary>
    public async Task<IReadOnlyList<TAccess>> ResolveAccessAsync<TResource, TAccess>(ClaimsPrincipal user,
        string permission, CancellationToken cancellationToken = default)
        where TResource : class where TAccess : class, IResourceAccess<TResource>
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!definition.Resources.TryGetValue(typeof(TResource), out var registration)
            || registration.AccessType != typeof(TAccess))
            throw new InvalidOperationException($"Resource '{typeof(TResource).Name}' must be registered with Access<{typeof(TAccess).Name}>().");
        var grants = await resolver.ResolveAsync(user, permission);
        cancellationToken.ThrowIfCancellationRequested();
        var alternatives = await registration.ResolveAlternativesAsync(permission, grants, services, cancellationToken);
        return Array.AsReadOnly(alternatives.Cast<TAccess>().ToArray());
    }

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
        var resolvedAccess = new Dictionary<Type, IReadOnlyList<object>>();
        foreach (var item in items)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var resource = resourceSelector(item);
            if (resource is null || !definition.Resources.TryGetValue(resource.GetType(), out var registration))
                continue;
            if (registration.AccessType is not null)
            {
                if (!resolvedAccess.TryGetValue(resource.GetType(), out var alternatives))
                {
                    alternatives = await registration.ResolveAlternativesAsync(permission, grants, services, cancellationToken);
                    resolvedAccess.Add(resource.GetType(), alternatives);
                }
                if (alternatives.Any(access => registration.AccessAllows!(access, resource))) result.Add(item);
                continue;
            }
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

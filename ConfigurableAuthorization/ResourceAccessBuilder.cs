using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;

namespace ConfigurableAuthorization;

/// <summary>Resolved constraints for one grant. The application translates these same constraints to its data store.</summary>
public interface IResourceAccess<in TResource> where TResource : class
{
    bool Allows(TResource resource);
}

/// <summary>Resolves access without needing an existing resource. Null denies this grant.</summary>
public interface IResourceAccessScope<TAccess> where TAccess : class
{
    ValueTask<TAccess?> ResolveAsync(ClaimsPrincipal user, CancellationToken cancellationToken);
}

public sealed class ResourceAccessBuilder<TResource, TGrant, TAccess>
    where TResource : class where TGrant : PermissionGrantOptions
    where TAccess : class, IResourceAccess<TResource>
{
    private readonly ResourceRegistration<TGrant> registration;
    internal ResourceAccessBuilder(ResourceRegistration<TGrant> registration) => this.registration = registration;

    public ResourceAccessBuilder<TResource, TGrant, TAccess> Scope(string name,
        Func<ClaimsPrincipal, TAccess?> resolve, Func<ClaimsPrincipal, bool>? eligible = null) =>
        AddScope(name, new(eligible ?? (_ => true), null,
            ResolveAccessAsync: (_, user, _) => ValueTask.FromResult<object?>(resolve(user))));

    /// <summary>Registers the implementation in DI with a scoped lifetime.</summary>
    public ResourceAccessBuilder<TResource, TGrant, TAccess> Scope<TScope>(string name,
        Func<ClaimsPrincipal, bool>? eligible = null) where TScope : class, IResourceAccessScope<TAccess> =>
        AddScope(name, new(eligible ?? (_ => true), null, typeof(TScope),
            async (services, user, cancellationToken) =>
                await services.GetRequiredService<TScope>().ResolveAsync(user, cancellationToken)));

    /// <summary>Narrows each grant's constraints. Return null to deny; never broaden the scope's access.</summary>
    public ResourceAccessBuilder<TResource, TGrant, TAccess> Constrain(
        Func<ClaimsPrincipal, TGrant, TAccess, TAccess?> constrain)
    {
        registration.Constraints.Add((user, grant, access) => constrain(user, grant, (TAccess)access));
        return this;
    }

    private ResourceAccessBuilder<TResource, TGrant, TAccess> AddScope(string name, ResourceScope scope)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        if (!registration.Scopes.TryAdd(name, scope))
            throw new ArgumentException($"Scope '{name}' is already registered for '{typeof(TResource).Name}'.");
        return this;
    }
}

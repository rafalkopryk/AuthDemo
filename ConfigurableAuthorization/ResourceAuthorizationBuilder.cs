using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;

namespace ConfigurableAuthorization;

/// <summary>Declares supported resources independently of configured role grants.</summary>
public sealed class ResourceAuthorizationBuilder<TGrant> where TGrant : PermissionGrantOptions
{
    public AuthorizationDefinition Definition { get; } = new();
    internal Dictionary<Type, ResourceRegistration<TGrant>> Resources { get; } = [];
    internal Func<ClaimsPrincipal, TGrant, bool> Eligible { get; private set; } = (_, _) => true;
    public void EvaluateWhen(Func<ClaimsPrincipal, TGrant, bool> eligible) => Eligible = eligible;

    internal Func<TGrant, IEnumerable<string>> ValidateGrant { get; private set; } = _ => [];

    public ResourceAuthorizationBuilder<TGrant> Service(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        Definition.ServiceName = name;
        return this;
    }

    public ResourceBuilder<TResource, TGrant> Resource<TResource>() where TResource : class
    {
        var registration = new ResourceRegistration<TGrant>();
        if (!Resources.TryAdd(typeof(TResource), registration))
            throw new ArgumentException($"Resource '{typeof(TResource).Name}' is already registered.");
        return new(registration, Definition);
    }

    /// <summary>Adds domain validation to startup validation of permissions and scopes.</summary>
    public void ValidateWith(Func<TGrant, IEnumerable<string>> validate) => ValidateGrant = validate;
}

public sealed class ResourceBuilder<TResource, TGrant> where TResource : class where TGrant : PermissionGrantOptions
{
    private readonly ResourceRegistration<TGrant> registration;
    private readonly AuthorizationDefinition definition;
    internal ResourceBuilder(ResourceRegistration<TGrant> registration, AuthorizationDefinition definition)
        => (this.registration, this.definition) = (registration, definition);

    public ResourceBuilder<TResource, TGrant> Permissions(params string[] permissions)
    {
        foreach (var permission in permissions)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(permission);
            registration.Permissions.Add(permission);
            definition.Permissions.Add(permission);
        }
        return this;
    }

    public ResourceBuilder<TResource, TGrant> AllowAll() => Scope("All", (_, _) => true);

    public ResourceBuilder<TResource, TGrant> Own(Func<TResource, Guid?> owner, string claim,
        Func<TResource, bool>? when = null) => MatchClaim("Own", owner, claim, when);

    public ResourceBuilder<TResource, TGrant> OwnBranch(Func<TResource, Guid?> branch, string claim,
        Func<TResource, bool>? when = null) => MatchClaim("OwnBranch", branch, claim, when);

    private ResourceBuilder<TResource, TGrant> MatchClaim(string scope, Func<TResource, Guid?> field,
        string claim, Func<TResource, bool>? when)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(claim);
        return Scope(scope, (user, resource) => IdentityClaims.ReadGuid(user, claim) is { } id
            && field(resource) == id && (when?.Invoke(resource) ?? true),
            eligible: user => IdentityClaims.ReadGuid(user, claim) is not null);
    }

    /// <summary>Extends the predefined scopes, for example for string identifiers or domain rules.</summary>
    public ResourceBuilder<TResource, TGrant> Scope(string name, Func<ClaimsPrincipal, TResource, bool> allows,
        Func<ClaimsPrincipal, bool>? eligible = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        if (!registration.Scopes.TryAdd(name, new(eligible ?? (_ => true),
            (_, user, resource, _) => ValueTask.FromResult(allows(user, (TResource)resource)))))
            throw new ArgumentException($"Scope '{name}' is already registered for '{typeof(TResource).Name}'.");
        return this;
    }

    /// <summary>Registers an asynchronous scope whose implementation can use scoped services.</summary>
    public ResourceBuilder<TResource, TGrant> Scope<TScope>(string name,
        Func<ClaimsPrincipal, bool>? eligible = null)
        where TScope : class, IResourceScope<TResource>
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        if (!registration.Scopes.TryAdd(name, new(eligible ?? (_ => true),
            (services, user, resource, cancellationToken) =>
                services.GetRequiredService<TScope>().AllowsAsync(user, (TResource)resource, cancellationToken),
            typeof(TScope))))
            throw new ArgumentException($"Scope '{name}' is already registered for '{typeof(TResource).Name}'.");
        return this;
    }

    /// <summary>All conditions must hold within the same grant as its scope.</summary>
    public ResourceBuilder<TResource, TGrant> Require(Func<ClaimsPrincipal, TGrant, TResource, bool> condition)
    {
        registration.Conditions.Add((user, grant, resource) => condition(user, grant, (TResource)resource));
        return this;
    }
}

internal sealed class ResourceRegistration<TGrant> where TGrant : PermissionGrantOptions
{
    internal HashSet<string> Permissions { get; } = new(StringComparer.Ordinal);
    internal Dictionary<string, ResourceScope> Scopes { get; } = new(StringComparer.Ordinal);
    internal List<Func<ClaimsPrincipal, TGrant, object, bool>> Conditions { get; } = [];

    internal async ValueTask<bool> AllowsAsync(string permission, object resource, ResourceGrant<TGrant> grant,
        IServiceProvider services, CancellationToken cancellationToken) =>
        Permissions.Contains(permission)
        && Scopes.TryGetValue(grant.Options.Scope, out var scope)
        && scope.Eligible(grant.User)
        && Conditions.All(condition => condition(grant.User, grant.Options, resource))
        && await scope.AllowsAsync(services, grant.User, resource, cancellationToken);
}

internal sealed record ResourceScope(
    Func<ClaimsPrincipal, bool> Eligible,
    Func<IServiceProvider, ClaimsPrincipal, object, CancellationToken, ValueTask<bool>> AllowsAsync,
    Type? ServiceType = null);

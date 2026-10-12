using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace LightAuthorization;

/// <summary>Creates constraints from the current user. Null denies this scope.</summary>
public interface IAccessProvider<TAccess> where TAccess : class
{
    ValueTask<TAccess?> ResolveAsync(ClaimsPrincipal user, CancellationToken cancellationToken);
}

/// <summary>Checks one existing resource. Use Access when the same scope must also filter queries.</summary>
public interface IResourceScope<in TResource> where TResource : class
{
    ValueTask<bool> AllowsAsync(ClaimsPrincipal user, TResource resource, CancellationToken cancellationToken);
}

public interface IAccessResolver<TResource, TAccess>
    where TResource : class
    where TAccess : class
{
    /// <summary>Returns OR alternatives. An empty list denies access.</summary>
    Task<IReadOnlyList<TAccess>> ResolveAsync(ClaimsPrincipal user, string permission,
        CancellationToken cancellationToken = default);
}

public sealed class ResourceBuilder<TResource> where TResource : class
{
    private readonly Action<Action<IServiceCollection>> register;
    private readonly Action<string> addScope;
    private readonly Dictionary<string, Func<IServiceProvider, ClaimsPrincipal, TResource, CancellationToken, ValueTask<bool>>> directScopes
        = new(StringComparer.Ordinal);
    private readonly HashSet<Type> directProviders = [];
    private bool accessConfigured;

    internal ResourceBuilder(Action<Action<IServiceCollection>> register, Action<string> addScope) =>
        (this.register, this.addScope) = (register, addScope);

    public ResourceAccessBuilder<TResource, TAccess> Access<TAccess>()
        where TAccess : class
    {
        if (accessConfigured || directScopes.Count > 0)
            throw new InvalidOperationException("Choose either direct scopes or Access for a resource.");
        accessConfigured = true;
        var builder = new ResourceAccessBuilder<TResource, TAccess>(addScope);
        register(builder.Register);
        return builder;
    }

    /// <summary>Checks an existing resource without resolving query constraints.</summary>
    public ResourceBuilder<TResource> Scope(string name, Func<ClaimsPrincipal, TResource, bool> allows)
    {
        ArgumentNullException.ThrowIfNull(allows);
        return Scope(name, (_, user, resource, _) => ValueTask.FromResult(allows(user, resource)));
    }

    /// <summary>Registers a scoped check with constructor injection.</summary>
    public ResourceBuilder<TResource> Scope<TScope>(string name)
        where TScope : class, IResourceScope<TResource>
    {
        Scope(name, (services, user, resource, token) =>
            services.GetRequiredService<TScope>().AllowsAsync(user, resource, token));
        directProviders.Add(typeof(TScope));
        return this;
    }

    /// <summary>Checks an existing resource with services and cancellation support.</summary>
    public ResourceBuilder<TResource> Scope(string name,
        Func<IServiceProvider, ClaimsPrincipal, TResource, CancellationToken, ValueTask<bool>> allows)
    {
        if (accessConfigured)
            throw new InvalidOperationException("Choose either direct scopes or Access for a resource.");
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(allows);
        if (!directScopes.TryAdd(name, allows))
            throw new ArgumentException($"Scope '{name}' is already registered for '{typeof(TResource).Name}'.");
        addScope(name);
        register(RegisterDirectScopes);
        return this;
    }

    private void RegisterDirectScopes(IServiceCollection services)
    {
        foreach (var provider in directProviders) services.TryAddScoped(provider);
        services.AddSingleton(new DirectScopeDefinition<TResource>(
            new Dictionary<string, Func<IServiceProvider, ClaimsPrincipal, TResource, CancellationToken, ValueTask<bool>>>(
                directScopes, StringComparer.Ordinal)));
        services.AddScoped<IAuthorizationHandler, DirectResourcePermissionHandler<TResource>>();
    }
}

internal sealed class DirectScopeDefinition<TResource>(
    IReadOnlyDictionary<string, Func<IServiceProvider, ClaimsPrincipal, TResource, CancellationToken, ValueTask<bool>>> scopes)
    where TResource : class
{
    public bool TryGet(string name,
        out Func<IServiceProvider, ClaimsPrincipal, TResource, CancellationToken, ValueTask<bool>>? allows) =>
        scopes.TryGetValue(name, out allows);
}

public sealed class ResourceAccessBuilder<TResource, TAccess>
    where TResource : class
    where TAccess : class
{
    private readonly Action<string> addScope;
    private readonly List<Func<TAccess, TResource, bool>> mappings = [];
    private readonly HashSet<Type> providers = [];
    private readonly Dictionary<string, Func<IServiceProvider, ClaimsPrincipal, CancellationToken, ValueTask<TAccess?>>> scopes
        = new(StringComparer.Ordinal);

    internal ResourceAccessBuilder(Action<string> addScope) => this.addScope = addScope;

    /// <summary>Null means unrestricted; an empty collection matches no resource. Mappings are ANDed.</summary>
    public ResourceAccessBuilder<TResource, TAccess> Map<TValue>(
        Func<TAccess, IEnumerable<TValue>?> values, Func<TResource, TValue> value)
    {
        ArgumentNullException.ThrowIfNull(values);
        ArgumentNullException.ThrowIfNull(value);
        mappings.Add((access, resource) => values(access) is not { } allowed || allowed.Contains(value(resource)));
        return this;
    }

    /// <summary>Maps an optional value constraint. Null means unrestricted.</summary>
    public ResourceAccessBuilder<TResource, TAccess> Map<TValue>(
        Func<TAccess, TValue?> constraint, Func<TResource, TValue> value) where TValue : struct
    {
        ArgumentNullException.ThrowIfNull(constraint);
        ArgumentNullException.ThrowIfNull(value);
        mappings.Add((access, resource) => constraint(access) is not { } allowed
            || EqualityComparer<TValue>.Default.Equals(allowed, value(resource)));
        return this;
    }

    public ResourceAccessBuilder<TResource, TAccess> Scope<TProvider>(string name)
        where TProvider : class, IAccessProvider<TAccess>
    {
        Scope(name, (services, user, token) => services.GetRequiredService<TProvider>().ResolveAsync(user, token));
        providers.Add(typeof(TProvider));
        return this;
    }

    public ResourceAccessBuilder<TResource, TAccess> Scope(string name, Func<ClaimsPrincipal, TAccess?> resolve)
    {
        ArgumentNullException.ThrowIfNull(resolve);
        return Scope(name, (_, user, _) => ValueTask.FromResult(resolve(user)));
    }

    public ResourceAccessBuilder<TResource, TAccess> Scope(string name,
        Func<IServiceProvider, ClaimsPrincipal, CancellationToken, ValueTask<TAccess?>> resolve)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(resolve);
        if (!scopes.TryAdd(name, resolve)) throw new ArgumentException($"Scope '{name}' is already registered.");
        addScope(name);
        return this;
    }

    internal void Register(IServiceCollection services)
    {
        if (mappings.Count == 0) throw new InvalidOperationException("Resource access needs at least one Map registration.");
        foreach (var provider in providers) services.TryAddScoped(provider);
        services.AddSingleton(new AccessMapping<TResource, TAccess>(mappings.ToArray()));
        if (scopes.Count == 0) throw new InvalidOperationException("Resource access needs at least one scope.");
        var factories = new Dictionary<string, Func<IServiceProvider, ClaimsPrincipal, CancellationToken, ValueTask<TAccess?>>>(scopes,
            StringComparer.Ordinal);
        services.AddScoped<IAccessResolver<TResource, TAccess>>(provider =>
            new AccessResolver<TResource, TAccess>(provider.GetRequiredService<LightAuthorizationDefinition>(), provider, factories));
        services.AddScoped<IAuthorizationHandler, ResourcePermissionHandler<TResource, TAccess>>();
    }
}

internal sealed class AccessResolver<TResource, TAccess>(LightAuthorizationDefinition definition,
    IServiceProvider services,
    IReadOnlyDictionary<string, Func<IServiceProvider, ClaimsPrincipal, CancellationToken, ValueTask<TAccess?>>> scopes)
    : IAccessResolver<TResource, TAccess>
    where TResource : class
    where TAccess : class
{
    public async Task<IReadOnlyList<TAccess>> ResolveAsync(ClaimsPrincipal user, string permission,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrWhiteSpace(permission);
        cancellationToken.ThrowIfCancellationRequested();
        var accesses = new List<TAccess>();
        foreach (var name in definition.Scopes(user, permission).Distinct(StringComparer.Ordinal))
        {
            if (!scopes.TryGetValue(name, out var resolve)) continue;
            cancellationToken.ThrowIfCancellationRequested();
            var access = await resolve(services, user, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            if (access is not null) accesses.Add(access);
        }
        return accesses.AsReadOnly();
    }
}

internal sealed class AccessMapping<TResource, TAccess>(IReadOnlyList<Func<TAccess, TResource, bool>> mappings)
{
    public bool Allows(TAccess access, TResource resource) => mappings.All(matches => matches(access, resource));
}

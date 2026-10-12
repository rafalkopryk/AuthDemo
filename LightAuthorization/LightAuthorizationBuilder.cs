using System.Security.Claims;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace LightAuthorization;

public sealed class LightAuthorizationBuilder
{
    private readonly Dictionary<string, List<Func<ClaimsPrincipal, bool>>> roles = new(StringComparer.Ordinal);
    private readonly List<(string Role, string Permission, string Scope)> permissions = [];
    private readonly Dictionary<Type, Action<IServiceCollection>> resources = [];
    private readonly HashSet<string> scopeNames = new(StringComparer.Ordinal);

    public LightAuthorizationBuilder MapRole(string role, Func<ClaimsPrincipal, bool> matches)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(role);
        ArgumentNullException.ThrowIfNull(matches);
        if (!roles.TryGetValue(role, out var predicates)) roles[role] = predicates = [];
        predicates.Add(matches);
        return this;
    }

    public LightAuthorizationBuilder MapRoleMappings(IConfigurationSection section,
        Func<ClaimsPrincipal, string?> actor)
    {
        ArgumentNullException.ThrowIfNull(section);
        ArgumentNullException.ThrowIfNull(actor);
        foreach (var entry in section.GetChildren())
        {
            var actorName = entry["Actor"];
            var claimType = entry["ClaimType"];
            var value = entry["Value"];
            var role = entry["Role"];
            if (string.IsNullOrWhiteSpace(actorName) || string.IsNullOrWhiteSpace(claimType)
                || string.IsNullOrWhiteSpace(value) || string.IsNullOrWhiteSpace(role))
                throw new InvalidOperationException($"Invalid role mapping at '{entry.Path}'.");
            MapRole(role, user => actor(user) == actorName && user.FindAll(claimType).Any(claim =>
                claimType == "scope"
                    ? claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries).Contains(value, StringComparer.Ordinal)
                    : claim.Value == value));
        }
        return this;
    }

    public LightAuthorizationBuilder Allow(string role, string permission, string scope)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(role);
        ArgumentException.ThrowIfNullOrWhiteSpace(permission);
        ArgumentException.ThrowIfNullOrWhiteSpace(scope);
        permissions.Add((role, permission, scope));
        return this;
    }

    public LightAuthorizationBuilder Roles(IConfigurationSection section)
    {
        ArgumentNullException.ThrowIfNull(section);
        foreach (var role in section.GetChildren())
        {
            if (string.IsNullOrWhiteSpace(role.Key))
                throw new InvalidOperationException($"Invalid role at '{role.Path}'.");
            foreach (var permission in role.GetChildren())
            {
                var names = permission.GetChildren().Select(scope => scope.Value).ToArray();
                if (names.Length == 0 && permission.Value is { } single) names = [single];
                if (names.Length == 0 || names.Any(string.IsNullOrWhiteSpace))
                    throw new InvalidOperationException($"Permission '{permission.Path}' needs at least one scope.");
                foreach (var name in names) Allow(role.Key, permission.Key, name!);
            }
        }
        return this;
    }

    public ResourceBuilder<TResource> Resource<TResource>() where TResource : class
    {
        if (!resources.TryAdd(typeof(TResource), _ =>
            throw new InvalidOperationException($"Resource '{typeof(TResource).Name}' needs a scope or Access registration.")))
            throw new ArgumentException($"Resource '{typeof(TResource).Name}' is already registered.");
        return new(register => resources[typeof(TResource)] = register, name => scopeNames.Add(name));
    }

    internal LightAuthorizationDefinition Build()
    {
        foreach (var (role, _, scope) in permissions)
        {
            if (!roles.ContainsKey(role)) throw new InvalidOperationException($"Role '{role}' has no mapping.");
            if (!scopeNames.Contains(scope))
                throw new InvalidOperationException($"Scope '{scope}' is not registered.");
        }
        return new(roles.ToDictionary(pair => pair.Key, pair => new List<Func<ClaimsPrincipal, bool>>(pair.Value),
            StringComparer.Ordinal), permissions.ToArray());
    }

    internal void RegisterHandlers(IServiceCollection services)
    {
        foreach (var register in resources.Values) register(services);
    }
}

internal sealed class LightAuthorizationDefinition(
    IReadOnlyDictionary<string, List<Func<ClaimsPrincipal, bool>>> roles,
    IReadOnlyList<(string Role, string Permission, string Scope)> permissions)
{
    public IEnumerable<string> Scopes(ClaimsPrincipal user, string permission)
    {
        if (user.Identity?.IsAuthenticated != true) yield break;
        foreach (var (role, assignedPermission, scope) in permissions)
            if (assignedPermission == permission && roles[role].Any(matches => matches(user))) yield return scope;
    }

}

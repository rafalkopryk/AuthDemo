using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace ConfigurableAuthorization.Tests;

public sealed class ResourceAccessTests
{
    private static readonly Guid Owner = Guid.NewGuid();
    private const string GrantPath = "Authorization:Roles:reader:Services:documents:Grants:";
    private static ClaimsPrincipal User(bool owner = true) => new(new ClaimsIdentity(
        owner ? [new Claim("actor_type", "person"), new Claim("client_id", Owner.ToString())]
              : [new Claim("actor_type", "person")], "test"));

    [Fact]
    public async Task All_entrypoints_preserve_correlated_grants_and_constraints()
    {
        using var provider = Provider(new()
        {
            [GrantPath + "1:Permissions:0"] = "documents.read",
            [GrantPath + "1:Scope"] = "All",
            [GrantPath + "1:Category"] = "public"
        });
        using var scope = provider.CreateScope();
        var resourceAuthorization = scope.ServiceProvider.GetRequiredService<ResourceAuthorization<DocumentGrant>>();
        var authorization = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        var accesses = await resourceAuthorization.ResolveAccessAsync<Document, DocumentAccess>(User(), "documents.read");
        Assert.Equal(2, accesses.Count);
        Document[] documents = [new(Owner, "secret"), new(Guid.NewGuid(), "public"),
            new(Guid.NewGuid(), "secret"), new(Owner, null)];
        var filtered = await resourceAuthorization.FilterAsync(User(), documents, "documents.read");
        Assert.Equal(documents.Take(2), filtered);
        foreach (var document in documents)
        {
            var allowed = (await authorization.AuthorizeAsync(User(), document,
                [new PermissionRequirement("documents.read")])).Succeeded;
            Assert.Equal(filtered.Contains(document), allowed);
            Assert.Equal(allowed, accesses.Any(a => a.Allows(document)));
        }
    }

    [Theory]
    [InlineData("denied")]
    [InlineData("empty")]
    public async Task EvaluateWhen_and_null_constraints_deny_every_entrypoint(string category)
    {
        using var provider = Provider(new() { [GrantPath + "0:Category"] = category });
        using var scope = provider.CreateScope();
        var resourceAuthorization = scope.ServiceProvider.GetRequiredService<ResourceAuthorization<DocumentGrant>>();
        Assert.Empty(await resourceAuthorization.ResolveAccessAsync<Document, DocumentAccess>(User(), "documents.read"));
        Assert.Empty(await resourceAuthorization.FilterAsync(User(), new[] { new Document(Owner, category) }, "documents.read"));
        Assert.False((await scope.ServiceProvider.GetRequiredService<IAuthorizationService>()
            .AuthorizeAsync(User(), new Document(Owner, category), [new PermissionRequirement("documents.read")])).Succeeded);
    }

    [Fact]
    public async Task Missing_scope_identity_and_missing_permission_do_not_grant_access()
    {
        using var provider = Provider();
        using var scope = provider.CreateScope();
        var authorization = scope.ServiceProvider.GetRequiredService<ResourceAuthorization<DocumentGrant>>();
        Assert.Empty(await authorization.ResolveAccessAsync<Document, DocumentAccess>(User(false), "documents.read"));
        Assert.Empty(await authorization.ResolveAccessAsync<Document, DocumentAccess>(User(), "documents.edit"));
        Assert.Empty(await authorization.ResolveAccessAsync<Document, DocumentAccess>(User(), "unknown"));
        Assert.Empty(await authorization.ResolveAccessAsync<Document, DocumentAccess>(new ClaimsPrincipal(), "documents.read"));
        Assert.Empty(await authorization.ResolveAccessAsync<Document, DocumentAccess>(
            new ClaimsPrincipal(new ClaimsIdentity([new Claim("actor_type", "unknown")], "test")), "documents.read"));
    }

    [Fact]
    public async Task Async_scope_uses_scoped_DI_and_resolves_once_per_collection()
    {
        using var provider = Provider(new() { [GrantPath + "0:Scope"] = "Directory" });
        using var scope = provider.CreateScope();
        var directory = scope.ServiceProvider.GetRequiredService<Directory>();
        var authorization = scope.ServiceProvider.GetRequiredService<ResourceAuthorization<DocumentGrant>>();
        using var cts = new CancellationTokenSource();
        var first = new Document(Owner, "secret");
        var items = new[] { new { Id = 1, Resource = first }, new { Id = 2, Resource = new Document(Guid.NewGuid(), "secret") } };
        var result = await authorization.FilterAsync(User(), items, item => item.Resource, "documents.read", cts.Token);
        Assert.Same(items[0], Assert.Single(result));
        Assert.Equal(1, directory.Calls);
        Assert.Equal(cts.Token, directory.Token);
        directory.OwnerId = null;
        Assert.Empty(await authorization.ResolveAccessAsync<Document, DocumentAccess>(User(), "documents.read"));
        using var anotherScope = provider.CreateScope();
        Assert.NotSame(directory, anotherScope.ServiceProvider.GetRequiredService<Directory>());
    }

    [Fact]
    public async Task Cancellation_is_checked_before_and_after_scope_resolution()
    {
        using var provider = Provider(new() { [GrantPath + "0:Scope"] = "Directory" });
        using var scope = provider.CreateScope();
        var authorization = scope.ServiceProvider.GetRequiredService<ResourceAuthorization<DocumentGrant>>();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            authorization.ResolveAccessAsync<Document, DocumentAccess>(User(), "documents.read", new(true)));
        using var cts = new CancellationTokenSource();
        scope.ServiceProvider.GetRequiredService<Directory>().OnResolve = cts.Cancel;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            authorization.ResolveAccessAsync<Document, DocumentAccess>(User(), "documents.read", cts.Token));
    }

    [Fact]
    public async Task Ineligible_scope_cannot_be_enabled_by_another_resource_with_the_same_permission()
    {
        using var provider = Provider(extraResource: true);
        using var scope = provider.CreateScope();
        // The other resource makes the grant eligible globally; the target must still check its own scope.
        Assert.Empty(await scope.ServiceProvider.GetRequiredService<ResourceAuthorization<DocumentGrant>>()
            .ResolveAccessAsync<Document, DocumentAccess>(User(false), "documents.read"));
    }

    [Fact]
    public async Task Unsupported_resource_registration_or_access_type_is_an_error()
    {
        using var provider = Provider(extraResource: true);
        using var scope = provider.CreateScope();
        var authorization = scope.ServiceProvider.GetRequiredService<ResourceAuthorization<DocumentGrant>>();
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            authorization.ResolveAccessAsync<Document, OtherAccess>(User(), "documents.read"));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            authorization.ResolveAccessAsync<OtherDocument, OtherAccess>(User(), "documents.read"));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            authorization.ResolveAccessAsync<UnregisteredDocument, OtherAccess>(User(), "documents.read"));
    }

    [Fact]
    public void Cannot_mix_typed_access_with_predicate_scopes_or_conditions_in_either_order()
    {
        var definition = new ResourceAuthorizationBuilder<PermissionGrantOptions>();
        var resource = definition.Resource<Document>().Permissions("documents.read");
        var access = resource.Access<DocumentAccess>().Scope("All", _ => new());
        Assert.Throws<InvalidOperationException>(() => resource.AllowAll());
        Assert.Throws<InvalidOperationException>(() => resource.Scope<PredicateScope>("Custom"));
        Assert.Throws<InvalidOperationException>(() => resource.Require((_, _, _) => true));
        Assert.Throws<InvalidOperationException>(() => resource.Access<DocumentAccess>());
        Assert.Throws<ArgumentException>(() => access.Scope("All", _ => new()));
        var direct = definition.Resource<OtherDocument>().Permissions("other.read");
        direct.AllowAll();
        Assert.Throws<InvalidOperationException>(() => direct.Access<OtherAccess>());
        var conditionOnly = definition.Resource<UnregisteredDocument>().Permissions("third.read");
        conditionOnly.Require((_, _, _) => true);
        Assert.Throws<InvalidOperationException>(() => conditionOnly.Access<OtherAccess>());
    }

    [Fact]
    public void Unknown_access_scope_is_rejected_by_configuration_validation()
    {
        using var provider = Provider(new() { [GrantPath + "0:Scope"] = "Unknown" });
        Assert.Throws<OptionsValidationException>(() =>
            provider.GetRequiredService<IOptions<AuthorizationOptions<DocumentGrant>>>().Value);
    }

    private static ServiceProvider Provider(Dictionary<string, string?>? overrides = null, bool extraResource = false)
    {
        var values = new Dictionary<string, string?>
        {
            ["Authorization:ActorRoles:person:0"] = "reader",
            [GrantPath + "0:Permissions:0"] = "documents.read",
            [GrantPath + "0:Scope"] = "Own",
            [GrantPath + "0:Category"] = "secret"
        };
        if (overrides is not null) foreach (var pair in overrides) values[pair.Key] = pair.Value;
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddScoped<Directory>();
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder().AddInMemoryCollection(values).Build());
        services.AddCreditAuthroization<DocumentGrant>(options =>
        {
            options.Service("documents");
            options.Definition.ActorTypes.Add("person");
            options.EvaluateWhen((_, grant) => grant.Category != "denied");
            options.Resource<Document>().Permissions("documents.read", "documents.edit")
                .Access<DocumentAccess>()
                .Scope("All", _ => new())
                .Scope("Own", user => IdentityClaims.ReadGuid(user, "client_id") is { } id ? new(OwnerId: id) : null,
                    eligible: user => IdentityClaims.ReadGuid(user, "client_id") is not null)
                .Scope<DirectoryScope>("Directory")
                .Constrain((_, grant, access) => grant.Category == "empty" ? null : access with { Category = grant.Category });
            if (extraResource)
                options.Resource<OtherDocument>().Permissions("documents.read").Scope("Own", (_, _) => true);
        });
        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
    }

    public sealed class DocumentGrant : PermissionGrantOptions
    {
        public string? Category { get; set; }
    }
    private sealed record Document(Guid OwnerId, string? Category);
    private sealed record DocumentAccess(Guid? OwnerId = null, string? Category = null) : IResourceAccess<Document>
    {
        public bool Allows(Document resource) => (OwnerId is null || resource.OwnerId == OwnerId)
            && (Category is null || resource.Category == Category);
    }
    private sealed class Directory
    {
        public Guid? OwnerId { get; set; } = Owner;
        public int Calls { get; set; }
        public CancellationToken Token { get; set; }
        public Action? OnResolve { get; set; }
    }
    private sealed class DirectoryScope(Directory directory) : IResourceAccessScope<DocumentAccess>
    {
        public async ValueTask<DocumentAccess?> ResolveAsync(ClaimsPrincipal user, CancellationToken cancellationToken)
        {
            directory.Calls++;
            directory.Token = cancellationToken;
            cancellationToken.ThrowIfCancellationRequested();
            await Task.Yield();
            directory.OnResolve?.Invoke();
            return directory.OwnerId is { } id ? new(OwnerId: id) : null;
        }
    }
    private sealed class PredicateScope : IResourceScope<Document>
    {
        public ValueTask<bool> AllowsAsync(ClaimsPrincipal user, Document resource, CancellationToken cancellationToken) =>
            ValueTask.FromResult(true);
    }
    private sealed record OtherDocument;
    private sealed record UnregisteredDocument;
    private sealed class OtherAccess : IResourceAccess<Document>, IResourceAccess<OtherDocument>, IResourceAccess<UnregisteredDocument>
    {
        public bool Allows(Document resource) => true;
        public bool Allows(OtherDocument resource) => true;
        public bool Allows(UnregisteredDocument resource) => true;
    }
}

using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace ConfigurableAuthorization.Tests;

public sealed class DocumentAuthorizationTests
{
    [Fact]
    public async Task Another_domain_uses_custom_claims_permissions_and_scopes()
    {
        using var provider = CreateProvider();
        using var scope = provider.CreateScope();
        var authorization = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        var user = User();
        Assert.True((await authorization.AuthorizeAsync(user, new Document("other", "secret"),
            [new PermissionRequirement("documents.read")])).Succeeded);
        Assert.True((await authorization.AuthorizeAsync(user, new Document("engineering", "secret"),
            [new PermissionRequirement("documents.edit")])).Succeeded);
        Assert.False((await authorization.AuthorizeAsync(user, new Document("other", "secret"),
            [new PermissionRequirement("documents.edit")])).Succeeded);
        Assert.False((await authorization.AuthorizeAsync(user, null,
            [new PermissionRequirement("documents.delete")])).Succeeded);
    }

    [Fact]
    public async Task Multiple_grants_preserve_their_team_and_classification_constraints()
    {
        using var provider = CreateProvider(new()
        {
            ["DocumentAccess:Roles:reviewer:Grants:0:Classification"] = "public",
            ["DocumentAccess:Roles:reviewer:Grants:1:Permissions:0"] = "documents.read",
            ["DocumentAccess:Roles:reviewer:Grants:1:Classification"] = "secret"
        });
        using var scope = provider.CreateScope();
        var authorization = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        Assert.True((await authorization.AuthorizeAsync(User(), new Document("other", "public"),
            [new PermissionRequirement("documents.read")])).Succeeded);
        Assert.True((await authorization.AuthorizeAsync(User(), new Document("engineering", "secret"),
            [new PermissionRequirement("documents.read")])).Succeeded);
        Assert.False((await authorization.AuthorizeAsync(User(), new Document("other", "secret"),
            [new PermissionRequirement("documents.read")])).Succeeded);
    }

    [Theory]
    [InlineData(0, true)]
    [InlineData(2, true)]
    [InlineData(1, false)]
    public async Task Missing_or_duplicate_actor_and_unauthenticated_principals_are_denied(int actorCount, bool authenticated)
    {
        using var provider = CreateProvider();
        using var scope = provider.CreateScope();
        var claims = new List<Claim> { new("groups", "reviewer"), new("department", "engineering") };
        claims.AddRange(Enumerable.Range(0, actorCount).Select(_ => new Claim("identity_kind", "person")));
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, authenticated ? "test" : null));
        Assert.Empty(await scope.ServiceProvider.GetRequiredService<IAccessResolver<DocumentAccess>>()
            .ResolveAsync(principal, "documents.read"));
    }

    [Fact]
    public async Task Missing_scope_attribute_does_not_remove_a_separate_valid_grant()
    {
        using var provider = CreateProvider();
        using var scope = provider.CreateScope();
        var user = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim("identity_kind", "person"), new Claim("groups", "reviewer")
        }, "test"));
        var resolver = scope.ServiceProvider.GetRequiredService<IAccessResolver<DocumentAccess>>();
        Assert.Single(await resolver.ResolveAsync(user, "documents.read"));
        Assert.Empty(await resolver.ResolveAsync(user, "documents.edit"));
    }

    [Fact]
    public async Task Transformation_is_idempotent_and_never_trusts_internal_claims_from_input()
    {
        using var provider = CreateProvider();
        var transformer = provider.GetRequiredService<IClaimsTransformation>();
        var user = User();
        ((ClaimsIdentity)user.Identity!).AddClaim(new Claim("internal_role", "administrator"));
        ((ClaimsIdentity)user.Identity!).AddClaim(new Claim("internal_permission", "documents.delete"));
        var once = await transformer.TransformAsync(user);
        var twice = await transformer.TransformAsync(once);
        Assert.True(twice.IsInRole("reviewer"));
        Assert.False(twice.IsInRole("administrator"));
        Assert.Single(twice.FindAll("internal_role"));
        Assert.Empty(twice.FindAll("internal_permission"));
        Assert.Equal(once.Identities.Count(), twice.Identities.Count());
        Assert.True(user.HasClaim("internal_role", "administrator"));
    }

    [Fact]
    public async Task Unsupported_resource_cannot_silently_become_a_permission_only_check()
    {
        using var provider = CreateProvider();
        using var scope = provider.CreateScope();
        var authorization = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        Assert.False((await authorization.AuthorizeAsync(User(), new object(),
            [new PermissionRequirement("documents.read")])).Succeeded);
        Assert.True((await authorization.AuthorizeAsync(User(), null,
            [new PermissionRequirement("documents.read")])).Succeeded);
    }

    [Theory]
    [InlineData("DocumentAccess:Roles:reviewer:Grants:0:Scope", "Unknown")]
    [InlineData("DocumentAccess:Roles:reviewer:Grants:0:Permissions:0", "documents.unknown")]
    [InlineData("DocumentAccess:RoleMappings:0:Role", "missing-role")]
    public void Both_core_and_domain_configuration_are_validated(string key, string value)
    {
        using var provider = CreateProvider(new() { [key] = value });
        Assert.Throws<OptionsValidationException>(() =>
            provider.GetRequiredService<IOptions<AuthorizationOptions<DocumentGrant>>>().Value);
    }

    private static ClaimsPrincipal User() => new(new ClaimsIdentity(new[]
    {
        new Claim("identity_kind", "person"), new Claim("groups", "unrelated reviewer"),
        new Claim("department", "engineering")
    }, "test"));

    private static ServiceProvider CreateProvider(Dictionary<string, string?>? overrides = null)
    {
        var values = new Dictionary<string, string?>
        {
            ["DocumentAccess:RoleMappings:0:Actor"] = "person",
            ["DocumentAccess:RoleMappings:0:ClaimType"] = "groups",
            ["DocumentAccess:RoleMappings:0:Value"] = "reviewer",
            ["DocumentAccess:RoleMappings:0:Role"] = "reviewer",
            ["DocumentAccess:Roles:reviewer:Grants:0:Permissions:0"] = "documents.read",
            ["DocumentAccess:Roles:reviewer:Grants:0:Scope"] = "All",
            ["DocumentAccess:Roles:reviewer:Grants:1:Permissions:0"] = "documents.edit",
            ["DocumentAccess:Roles:reviewer:Grants:1:Scope"] = "Team"
        };
        if (overrides is not null)
            foreach (var pair in overrides) values[pair.Key] = pair.Value;
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder().AddInMemoryCollection(values).Build());
        services.AddCreditAuthroization<DocumentGrant, DocumentAccess, DocumentGrantEvaluator>(definition =>
        {
            definition.Permissions.UnionWith(["documents.read", "documents.edit"]);
            definition.ActorTypes.Add("person");
            definition.ActorClaimType = "identity_kind";
            definition.InternalClaimPrefix = "internal_";
            definition.RoleClaimType = "internal_role";
            definition.SpaceSeparatedClaimTypes.Add("groups");
        }, "DocumentAccess");
        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
    }

    public sealed class DocumentGrant : PermissionGrantOptions
    {
        public string? Classification { get; set; }
    }

    public sealed record DocumentAccess(string? Team, string? Classification);

    public sealed class DocumentGrantEvaluator : IGrantEvaluator<DocumentGrant, DocumentAccess>
    {
        public IEnumerable<string> Validate(DocumentGrant grant) =>
            grant.Scope is "All" or "Team" ? [] : ["Unknown document scope."];

        public DocumentAccess? Evaluate(ClaimsPrincipal user, DocumentGrant grant) => grant.Scope switch
        {
            "All" => new(null, grant.Classification),
            "Team" when IdentityClaims.Find(user, "department").ToArray() is [var team] =>
                new(team.Value, grant.Classification),
            _ => null
        };
    }

    private sealed record Document(string Team, string Classification) : IAuthorizationResource<DocumentAccess>
    {
        public bool Authorize(string permission, IReadOnlyList<DocumentAccess> grants) => grants.Any(grant =>
            (grant.Team is null || grant.Team == Team)
            && (grant.Classification is null || grant.Classification == Classification));
    }
}

using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace ConfigurableAuthorization.Tests;

public sealed class ResourceAuthorizationTests
{
    private static readonly Guid Owner = Guid.NewGuid();
    private static readonly Guid Branch = Guid.NewGuid();
    private const string Grant = "Authorization:Roles:operator:Services:documents:Grants:";

    [Fact]
    public async Task Plain_resource_uses_predefined_scopes_without_implementing_an_interface()
    {
        using var provider = Provider();
        using var scope = provider.CreateScope();
        var authorization = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        Assert.True(await Allows(authorization, new Document(Owner, Branch, "branch", "public")));
        Assert.False(await Allows(authorization, new Document(Guid.NewGuid(), Branch, "branch", "public")));
        Assert.False(await Allows(authorization, new Document(Owner, Branch, "branch", "secret")));
        Assert.False(await Allows(authorization, new Document(Owner, Branch, "branch", "public"), permission: "documents.edit"));
    }

    [Fact]
    public async Task Branch_scope_checks_claim_and_resource_condition()
    {
        using var provider = Provider(new() { [Grant + "0:Scope"] = "OwnBranch" });
        using var scope = provider.CreateScope();
        var authorization = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        Assert.True(await Allows(authorization, new Document(Guid.NewGuid(), Branch, "branch", "public")));
        Assert.False(await Allows(authorization, new Document(Owner, Branch, "digital", "public")));
        Assert.False(await Allows(authorization, new Document(Owner, Guid.NewGuid(), "branch", "public")));
        Assert.False(await Allows(authorization, new Document(Owner, null, "branch", "public")));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("invalid")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    [InlineData("duplicate")]
    public async Task Missing_invalid_or_ambiguous_owner_claim_is_denied(string? value)
    {
        var claims = value == "duplicate"
            ? new[] { new Claim("client_id", Owner.ToString()), new Claim("client_id", Owner.ToString()) }
            : value is null ? [] : new[] { new Claim("client_id", value) };
        using var provider = Provider();
        using var scope = provider.CreateScope();
        Assert.False(await Allows(scope.ServiceProvider.GetRequiredService<IAuthorizationService>(),
            new Document(Owner, Branch, "branch", "public"), User(claims)));
    }

    [Fact]
    public async Task Null_http_context_unknown_and_unregistered_derived_resources_are_denied()
    {
        using var provider = Provider();
        using var scope = provider.CreateScope();
        var authorization = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        foreach (var resource in new object?[] { null, new DefaultHttpContext(), new object(),
            new DerivedDocument(Owner, Branch, "branch", "public") })
            Assert.False(await Allows(authorization, resource));
        Assert.True((await authorization.AuthorizeAsync(User(), new DefaultHttpContext(),
            [new PermissionPresenceRequirement("documents.read")])).Succeeded);
        Assert.False((await authorization.AuthorizeAsync(User(), null,
            [new PermissionPresenceRequirement("documents.edit")])).Succeeded);
    }

    [Fact]
    public async Task All_scope_still_requires_authenticated_mapped_identity_and_grant_conditions()
    {
        using var provider = Provider(new() { [Grant + "0:Scope"] = "All" });
        using var scope = provider.CreateScope();
        var authorization = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        var document = new Document(Guid.NewGuid(), null, "digital", "public");
        Assert.True(await Allows(authorization, document, User([])));
        Assert.False(await Allows(authorization, document, new ClaimsPrincipal(new ClaimsIdentity(User().Claims))));
        Assert.False(await Allows(authorization, document, new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("actor_type", "person"), new Claim("app_role", "operator")], "test"))));
    }

    [Theory]
    [InlineData("0:Scope", "Unknown")]
    [InlineData("0:Permissions:0", "documents.unknown")]
    public void Unknown_scope_or_permission_fails_configuration_validation(string suffix, string value)
    {
        using var provider = Provider(new() { [Grant + suffix] = value });
        Assert.Throws<OptionsValidationException>(() =>
            provider.GetRequiredService<IOptions<AuthorizationOptions<DocumentGrant>>>().Value);
    }

    [Fact]
    public void Every_resource_for_a_permission_must_support_the_configured_scope()
    {
        using var provider = Provider(extraResource: true);
        var error = Assert.Throws<OptionsValidationException>(() =>
            provider.GetRequiredService<IOptions<AuthorizationOptions<DocumentGrant>>>().Value);
        Assert.Contains(nameof(OtherDocument), error.Message);
        Assert.Contains("Own", error.Message);
    }

    [Fact]
    public async Task Other_services_with_different_schemas_do_not_grant_local_access()
    {
        using var provider = Provider(new()
        {
            ["Authorization:Roles:operator:Services:payments:Grants:0:Permissions:0"] = "documents.edit",
            ["Authorization:Roles:operator:Services:payments:Grants:0:Scope"] = "PaymentTeam",
            ["Authorization:Roles:operator:Services:payments:Grants:0:PaymentSpecificSetting"] = "anything"
        });
        using var scope = provider.CreateScope();
        var authorization = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        var document = new Document(Owner, Branch, "branch", "public");
        Assert.True(await Allows(authorization, document));
        Assert.False(await Allows(authorization, document, permission: "documents.edit"));
    }

    [Fact]
    public async Task Filter_preserves_whole_grants_and_matches_single_resource_authorization()
    {
        using var provider = Provider(new()
        {
            [Grant + "1:Permissions:0"] = "documents.read",
            [Grant + "1:Scope"] = "OwnBranch",
            [Grant + "1:Classification"] = "secret"
        });
        using var scope = provider.CreateScope();
        var authorization = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        Document[] documents = [new(Owner, null, "digital", "public"),
            new(Guid.NewGuid(), Branch, "branch", "secret"),
            new(Owner, null, "digital", "secret"),
            new(Guid.NewGuid(), Branch, "branch", "public")];
        var filtered = await scope.ServiceProvider.GetRequiredService<ResourceAuthorization<DocumentGrant>>()
            .FilterAsync(User(), documents, "documents.read");
        Assert.Equal(documents.Take(2), filtered);
        foreach (var document in documents)
            Assert.Equal(filtered.Contains(document), await Allows(authorization, document));
    }

    [Fact]
    public async Task Basic_integration_needs_no_custom_grant_or_evaluator()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Authorization:ActorRoles:person:0"] = "reader",
            ["Authorization:Roles:reader:Services:documents:Grants:0:Permissions:0"] = "documents.read",
            ["Authorization:Roles:reader:Services:documents:Grants:0:Scope"] = "Own"
        }).Build());
        services.AddCreditAuthroization(options =>
        {
            options.Service("documents");
            options.Definition.ActorTypes.Add("person");
            options.Resource<Document>().Permissions("documents.read").Own(d => d.Owner, "client_id");
        });
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
        using var scope = provider.CreateScope();
        Assert.True(await Allows(scope.ServiceProvider.GetRequiredService<IAuthorizationService>(),
            new Document(Owner, null, "digital", "public")));
    }

    [Fact]
    public async Task Filter_can_project_dedicated_resources_and_returns_the_original_items()
    {
        using var provider = Provider();
        using var scope = provider.CreateScope();
        var allowed = new { Id = 1, Resource = new Document(Owner, Branch, "branch", "public") };
        var denied = new { Id = 2, Resource = new Document(Guid.NewGuid(), Branch, "branch", "public") };
        var authorization = scope.ServiceProvider.GetRequiredService<ResourceAuthorization<DocumentGrant>>();
        var result = await authorization.FilterAsync(User(), new[] { denied, allowed },
            item => item.Resource, "documents.read");
        Assert.Same(allowed, Assert.Single(result));
    }

    [Fact]
    public async Task Missing_scope_identity_is_also_denied_by_the_preliminary_permission_check()
    {
        using var provider = Provider();
        using var scope = provider.CreateScope();
        var authorization = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        Assert.False((await authorization.AuthorizeAsync(User([]), null,
            [new PermissionPresenceRequirement("documents.read")])).Succeeded);
    }

    [Fact]
    public async Task Ineligible_own_grant_does_not_remove_an_independent_all_grant()
    {
        using var provider = Provider(new()
        {
            [Grant + "1:Permissions:0"] = "documents.read",
            [Grant + "1:Scope"] = "All",
            [Grant + "1:Classification"] = "secret"
        });
        using var scope = provider.CreateScope();
        Assert.True(await Allows(scope.ServiceProvider.GetRequiredService<IAuthorizationService>(),
            new Document(Guid.NewGuid(), null, "digital", "secret"), User([])));
    }

    private static async Task<bool> Allows(IAuthorizationService service, object? resource,
        ClaimsPrincipal? user = null, string permission = "documents.read") =>
        (await service.AuthorizeAsync(user ?? User(), resource, [new PermissionRequirement(permission)])).Succeeded;

    private static ClaimsPrincipal User(Claim[]? identityClaims = null) => new(new ClaimsIdentity(
        new Claim[] { new("actor_type", "person"), new("groups", "operators"), new("branch_id", Branch.ToString()) }
            .Concat(identityClaims ?? [new("client_id", Owner.ToString())]), "test"));

    private static ServiceProvider Provider(Dictionary<string, string?>? overrides = null, bool extraResource = false)
    {
        var values = new Dictionary<string, string?>
        {
            ["Authorization:RoleMappings:0:Actor"] = "person",
            ["Authorization:RoleMappings:0:ClaimType"] = "groups",
            ["Authorization:RoleMappings:0:Value"] = "operators",
            ["Authorization:RoleMappings:0:Role"] = "operator",
            [Grant + "0:Permissions:0"] = "documents.read",
            [Grant + "0:Scope"] = "Own",
            [Grant + "0:Classification"] = "public"
        };
        if (overrides is not null) foreach (var pair in overrides) values[pair.Key] = pair.Value;
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder().AddInMemoryCollection(values).Build());
        services.AddCreditAuthroization<DocumentGrant>(options =>
        {
            options.Service("documents");
            options.Definition.ActorTypes.Add("person");
            options.Resource<Document>().Permissions("documents.read", "documents.edit")
                .AllowAll().Own(d => d.Owner, "client_id")
                .OwnBranch(d => d.Branch, "branch_id", d => d.Channel == "branch")
                .Require((_, grant, document) => grant.Classification is null || grant.Classification == document.Classification);
            if (extraResource) options.Resource<OtherDocument>().Permissions("documents.read").AllowAll();
        });
        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
    }

    public sealed class DocumentGrant : PermissionGrantOptions
    {
        public string? Classification { get; set; }
    }
    private record Document(Guid Owner, Guid? Branch, string Channel, string Classification);
    private sealed record DerivedDocument(Guid Owner, Guid? Branch, string Channel, string Classification)
        : Document(Owner, Branch, Channel, Classification);
    private sealed record OtherDocument;
}

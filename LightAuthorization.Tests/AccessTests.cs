using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace LightAuthorization.Tests;

public sealed class AccessTests
{
    private sealed record Document(string Owner);
    private sealed record Access(string[]? Owners = null);

    private static ClaimsPrincipal User(string? role = "reader", bool authenticated = true) =>
        new(new ClaimsIdentity(role is null ? [] : [new Claim("role", role)], authenticated ? "test" : null));

    private static ServiceCollection Services()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        return services;
    }

    [Theory]
    [InlineData("reader", true, "read", 1, true, false)]
    [InlineData("admin", true, "read", 1, true, true)]
    [InlineData("both", true, "read", 2, true, true)]
    [InlineData("reader", false, "read", 0, false, false)]
    [InlineData(null, true, "read", 0, false, false)]
    [InlineData("reader", true, "write", 0, false, false)]
    [InlineData("reader", true, "Read", 0, false, false)]
    [InlineData("denied", true, "read", 0, false, false)]
    public async Task Resolver_and_standard_handler_agree(string? role, bool authenticated, string permission,
        int count, bool own, bool other)
    {
        var services = Services();
        services.AddLightAuthorization(options =>
        {
            options.MapRole("reader", user => user.HasClaim("role", "reader") || user.HasClaim("role", "both"));
            options.MapRole("admin", user => user.HasClaim("role", "admin") || user.HasClaim("role", "both"));
            options.MapRole("denied", user => user.HasClaim("role", "denied"));
            options.Allow("reader", "read", "Own").Allow("admin", "read", "All").Allow("denied", "read", "Denied");
            options.Resource<Document>().Access<Access>().Map(access => access.Owners, resource => resource.Owner)
                .Scope("Own", _ => new Access(["alice"]))
                .Scope("All", _ => new Access())
                .Scope("Denied", _ => null);
        });
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        using var scope = provider.CreateScope();
        var user = User(role, authenticated);
        var accesses = await scope.ServiceProvider.GetRequiredService<IAccessResolver<Document, Access>>()
            .ResolveAsync(user, permission);
        Assert.Equal(count, accesses.Count);
        var authorization = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        foreach (var (document, expected) in new[] { (new Document("alice"), own), (new Document("bob"), other) })
        {
            Assert.Equal(expected, accesses.Any(access => access.Owners is null || access.Owners.Contains(document.Owner)));
            Assert.Equal(expected, (await authorization.AuthorizeAsync(user, document,
                [new ResourcePermissionRequirement(permission)])).Succeeded);
        }
    }

    private sealed class ScopedOwner
    {
        public string Id { get; } = Guid.NewGuid().ToString();
    }

    [Fact]
    public async Task Async_factory_uses_current_scope_and_token_and_runs_once_per_named_scope()
    {
        using var cancellation = new CancellationTokenSource();
        var calls = 0;
        var services = Services();
        services.AddScoped<ScopedOwner>();
        services.AddLightAuthorization(options =>
        {
            options.MapRole("reader", _ => true).MapRole("also-reader", _ => true);
            options.Allow("reader", "read", "Own").Allow("also-reader", "read", "Own");
            options.Resource<Document>().Access<Access>().Map(access => access.Owners, resource => resource.Owner).Scope("Own", async (provider, _, token) =>
            {
                await Task.Yield();
                Assert.Equal(cancellation.Token, token);
                calls++;
                return new Access([provider.GetRequiredService<ScopedOwner>().Id]);
            });
        });
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        using var first = provider.CreateScope();
        using var second = provider.CreateScope();
        foreach (var scope in new[] { first, second })
        {
            var access = Assert.Single(await scope.ServiceProvider.GetRequiredService<IAccessResolver<Document, Access>>()
                .ResolveAsync(User(), "read", cancellation.Token));
            Assert.Equal(scope.ServiceProvider.GetRequiredService<ScopedOwner>().Id, Assert.Single(access.Owners!));
        }
        Assert.NotEqual(first.ServiceProvider.GetRequiredService<ScopedOwner>().Id,
            second.ServiceProvider.GetRequiredService<ScopedOwner>().Id);
        Assert.Equal(2, calls);
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first.ServiceProvider
            .GetRequiredService<IAccessResolver<Document, Access>>().ResolveAsync(User(), "read", cancellation.Token));
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task Cancellation_after_factory_cannot_return_access()
    {
        using var cancellation = new CancellationTokenSource();
        var services = Services();
        services.AddLightAuthorization(options =>
        {
            options.MapRole("reader", _ => true).Allow("reader", "read", "All");
            options.Resource<Document>().Access<Access>().Map(access => access.Owners, resource => resource.Owner).Scope("All", (_, _, _) =>
            {
                cancellation.Cancel();
                return ValueTask.FromResult<Access?>(new Access());
            });
        });
        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => scope.ServiceProvider
            .GetRequiredService<IAccessResolver<Document, Access>>().ResolveAsync(User(), "read", cancellation.Token));
    }

    [Theory]
    [InlineData("duplicate-resource")]
    [InlineData("duplicate-access")]
    [InlineData("duplicate-scope")]
    [InlineData("unknown-scope")]
    [InlineData("unknown-role")]
    [InlineData("missing-access")]
    [InlineData("missing-scopes")]
    public void Invalid_registration_fails_at_startup(string scenario)
    {
        Assert.ThrowsAny<Exception>(() => Services().AddLightAuthorization(options =>
        {
            options.MapRole("reader", _ => true);
            var resource = options.Resource<Document>();
            if (scenario == "missing-access") return;
            var access = resource.Access<Access>().Map(access => access.Owners, resource => resource.Owner);
            if (scenario == "missing-scopes") return;
            access.Scope("Own", _ => new Access(["alice"]));
            switch (scenario)
            {
                case "duplicate-resource": options.Resource<Document>(); break;
                case "duplicate-access": resource.Access<Access>().Map(access => access.Owners, resource => resource.Owner); break;
                case "duplicate-scope": access.Scope("Own", _ => null); break;
                case "unknown-scope": options.Allow("reader", "read", "Missing"); break;
                case "unknown-role": options.Allow("missing", "read", "Own"); break;
            }
        }));
    }
}

using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace LightAuthorization.Tests;

public sealed class DirectScopeTests
{
    private sealed record Account(Guid CustomerId, Guid BranchId);
    private sealed record AccountAccess(Guid? CustomerId = null);

    private static readonly Guid Customer = Guid.NewGuid();
    private static readonly Guid Other = Guid.NewGuid();
    private static readonly Guid Branch = Guid.NewGuid();
    private static readonly Guid ForeignBranch = Guid.NewGuid();

    private static ClaimsPrincipal User(string? role, bool authenticated = true) =>
        new(new ClaimsIdentity(role is null ? [] : [new Claim("role", role)], authenticated ? "test" : null));

    private sealed class EmployeeBranches
    {
        public Guid[] Ids { get; } = [Branch];
    }

    private sealed class BranchScope(EmployeeBranches branches) : IResourceScope<Account>
    {
        public int Calls { get; private set; }
        public ValueTask<bool> AllowsAsync(ClaimsPrincipal user, Account resource, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            return ValueTask.FromResult(branches.Ids.Contains(resource.BranchId));
        }
    }

    private static ServiceProvider CreateProvider()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Authorization:Roles:owner:close:0"] = "Own",
            ["Authorization:Roles:employee:close:0"] = "Branch",
            ["Authorization:Roles:both:close:0"] = "Own",
            ["Authorization:Roles:both:close:1"] = "Branch"
        }).Build();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddScoped<EmployeeBranches>();
        services.AddLightAuthorization(options =>
        {
            options.MapRole("owner", user => user.HasClaim("role", "owner"));
            options.MapRole("employee", user => user.HasClaim("role", "employee"));
            options.MapRole("both", user => user.HasClaim("role", "both"));
            options.Roles(configuration.GetSection("Authorization:Roles"));
            options.Resource<Account>()
                .Scope("Own", (_, account) => account.CustomerId == Customer)
                .Scope<BranchScope>("Branch");
        });
        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
    }

    [Theory]
    [InlineData("owner", true, false, true)]
    [InlineData("employee", false, true, true)]
    [InlineData("employee", false, false, false)]
    [InlineData("both", true, false, true)]
    [InlineData("both", false, true, true)]
    [InlineData("owner", false, true, false)]
    [InlineData(null, true, true, false)]
    public async Task Direct_scopes_authorize_existing_resource_without_access(
        string? role, bool own, bool branch, bool expected)
    {
        using var provider = CreateProvider();
        using var scope = provider.CreateScope();
        var resource = new Account(own ? Customer : Other, branch ? Branch : ForeignBranch);
        var result = await scope.ServiceProvider.GetRequiredService<IAuthorizationService>()
            .AuthorizeAsync(User(role), resource, [new ResourcePermissionRequirement("close")]);
        Assert.Equal(expected, result.Succeeded);
        Assert.Null(scope.ServiceProvider.GetService<IAccessResolver<Account, AccountAccess>>());
    }

    [Fact]
    public async Task Unauthenticated_and_unassigned_users_are_denied()
    {
        using var provider = CreateProvider();
        using var scope = provider.CreateScope();
        var authorization = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        foreach (var (user, permission) in new[] { (User("owner", false), "close"), (User("owner"), "read") })
        {
            var result = await authorization.AuthorizeAsync(user, new Account(Customer, Branch),
                [new ResourcePermissionRequirement(permission)]);
            Assert.False(result.Succeeded);
        }
    }

    [Fact]
    public async Task Scope_class_is_scoped_and_resolved_only_when_eligible()
    {
        using var provider = CreateProvider();
        using var first = provider.CreateScope();
        using var second = provider.CreateScope();
        var authorization = first.ServiceProvider.GetRequiredService<IAuthorizationService>();
        var account = new Account(Other, Branch);
        Assert.True((await authorization.AuthorizeAsync(User("employee"), account,
            [new ResourcePermissionRequirement("close")])).Succeeded);
        var instance = first.ServiceProvider.GetRequiredService<BranchScope>();
        Assert.Equal(1, instance.Calls);
        Assert.False((await authorization.AuthorizeAsync(User("owner"), account,
            [new ResourcePermissionRequirement("close")])).Succeeded);
        Assert.Equal(1, instance.Calls);
        Assert.NotSame(instance, second.ServiceProvider.GetRequiredService<BranchScope>());
    }

    [Fact]
    public void Direct_and_access_scopes_cannot_be_mixed_for_one_resource()
    {
        Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddLightAuthorization(options =>
            options.Resource<Account>().Scope("Own", (_, _) => true).Access<AccountAccess>()));
        Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddLightAuthorization(options =>
        {
            var resource = options.Resource<Account>();
            resource.Access<AccountAccess>();
            resource.Scope("Own", (_, _) => true);
        }));
    }
}

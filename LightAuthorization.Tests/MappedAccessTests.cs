using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace LightAuthorization.Tests;

public sealed class MappedAccessTests
{
    private sealed record Account(int CustomerId, int BranchId, string Product);
    private sealed record AccountAccess(int[]? CustomerIds = null, int[]? BranchIds = null, string[]? Products = null);
    private static ClaimsPrincipal User => new(new ClaimsIdentity([], "test"));

    [Theory]
    [InlineData(1, 10, "deposit", true)]
    [InlineData(2, 20, "loan", true)]
    [InlineData(1, 20, "deposit", false)]
    [InlineData(2, 10, "loan", false)]
    [InlineData(1, 10, "loan", false)]
    [InlineData(3, 10, "deposit", false)]
    public async Task Configured_alternatives_keep_fields_together(int customer, int branch, string product, bool expected)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Authorization:Roles:employee:accounts.read:0"] = "First",
            ["Authorization:Roles:employee:accounts.read:1"] = "Second"
        }).Build();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddLightAuthorization(options =>
        {
            options.MapRole("employee", _ => true);
            options.Roles(configuration.GetSection("Authorization:Roles"));
            options.Resource<Account>().Access<AccountAccess>()
                .Map(access => access.CustomerIds, resource => resource.CustomerId)
                .Map(access => access.BranchIds, resource => resource.BranchId)
                .Map(access => access.Products, resource => resource.Product)
                .Scope("First", _ => new AccountAccess([1], [10], ["deposit"]))
                .Scope("Second", _ => new AccountAccess([2], [20], ["loan"]));
        });
        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var accesses = await scope.ServiceProvider.GetRequiredService<IAccessResolver<Account, AccountAccess>>()
            .ResolveAsync(User, "accounts.read");
        Assert.Equal(2, accesses.Count);
        var result = await scope.ServiceProvider.GetRequiredService<IAuthorizationService>().AuthorizeAsync(
            User, new Account(customer, branch, product), [new ResourcePermissionRequirement("accounts.read")]);
        Assert.Equal(expected, result.Succeeded);
    }

    [Theory]
    [InlineData("All", true)]
    [InlineData("Empty", false)]
    [InlineData("Denied", false)]
    public async Task Null_field_is_unrestricted_but_empty_collection_and_null_access_deny(string name, bool expected)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddLightAuthorization(options =>
        {
            options.MapRole("employee", _ => true).Allow("employee", "read", name);
            options.Resource<Account>().Access<AccountAccess>()
                .Map(access => access.CustomerIds, resource => resource.CustomerId)
                .Map(access => access.BranchIds, resource => resource.BranchId)
                .Scope("All", _ => new AccountAccess())
                .Scope("Empty", _ => new AccountAccess(BranchIds: []))
                .Scope("Denied", _ => null);
        });
        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var result = await scope.ServiceProvider.GetRequiredService<IAuthorizationService>()
            .AuthorizeAsync(User, new Account(1, 10, "deposit"), [new ResourcePermissionRequirement("read")]);
        Assert.Equal(expected, result.Succeeded);
    }

    private sealed class EmployeeBranches
    {
        public int[] Ids { get; } = [10, 20];
    }

    private sealed class BranchProvider(EmployeeBranches branches) : IAccessProvider<AccountAccess>
    {
        public CancellationToken LastToken { get; private set; }

        public async ValueTask<AccountAccess?> ResolveAsync(ClaimsPrincipal user, CancellationToken cancellationToken)
        {
            await Task.Yield();
            LastToken = cancellationToken;
            return new AccountAccess(BranchIds: branches.Ids);
        }
    }

    [Fact]
    public async Task Provider_registration_is_scoped_and_preserves_dependency_injection_and_cancellation_token()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddScoped<EmployeeBranches>();
        services.AddLightAuthorization(options =>
        {
            options.MapRole("employee", _ => true).Allow("employee", "read", "Branch");
            options.Resource<Account>().Access<AccountAccess>()
                .Map(access => access.BranchIds, resource => resource.BranchId)
                .Scope<BranchProvider>("Branch")
                .Scope<BranchProvider>("SameProvider");
        });
        Assert.Single(services, service => service.ServiceType == typeof(BranchProvider));
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        using var first = provider.CreateScope();
        using var second = provider.CreateScope();
        using var cancellation = new CancellationTokenSource();
        var access = Assert.Single(await first.ServiceProvider.GetRequiredService<IAccessResolver<Account, AccountAccess>>()
            .ResolveAsync(User, "read", cancellation.Token));
        Assert.Same(first.ServiceProvider.GetRequiredService<EmployeeBranches>().Ids, access.BranchIds);
        Assert.Equal(cancellation.Token, first.ServiceProvider.GetRequiredService<BranchProvider>().LastToken);
        Assert.NotSame(first.ServiceProvider.GetRequiredService<BranchProvider>(), second.ServiceProvider.GetRequiredService<BranchProvider>());
    }

    [Fact]
    public void Missing_maps_are_rejected_instead_of_granting_everything()
    {
        Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddLightAuthorization(options =>
            options.Resource<Account>().Access<AccountAccess>().Scope("All", _ => new AccountAccess())));
    }
}

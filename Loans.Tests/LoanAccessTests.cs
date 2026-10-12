using System.Security.Claims;
using LightAuthorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Loans.Features.LoanApplications;
using Loans.Features.LoanApplications.Authorization;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace Loans.Tests;

public sealed class LoanAccessTests
{
    private static readonly Guid Owner = Guid.NewGuid();
    private static readonly Guid Other = Guid.NewGuid();

    [Fact]
    public async Task Reader_filters_before_pagination_and_matches_resource_access()
    {
        await using var db = new LoansDbContext(new DbContextOptionsBuilder<LoansDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);
        var entries = Enumerable.Range(0, 6).Select(index => new LoanApplicationEntity
        {
            Id = Guid.NewGuid(), ClientId = index % 2 == 0 ? Owner : Other,
            CreatedAt = DateTimeOffset.UtcNow.AddMinutes(index), ApplicantName = "Test"
        }).ToArray();
        db.LoanApplications.AddRange(entries);
        await db.SaveChangesAsync();
        var reader = new LoanApplicationReader(db);
        foreach (var accesses in new LoanAccess[][] { [], [new(Owner)], [new(Other)], [new(Owner), new(Other)], [new()] })
        {
            var query = new ListLoanApplicationsQuery(Skip: 1, Take: 2);
            var expected = entries.Where(entry => accesses.Any(access => access.ClientId is null || access.ClientId == entry.ClientId))
                .OrderByDescending(entry => entry.CreatedAt).ThenBy(entry => entry.Id).Skip(1).Take(2).Select(entry => entry.Id);
            Assert.Equal(expected, (await reader.SearchAsync(query, accesses, default)).Select(entry => entry.Id));
        }
        Assert.Empty(await reader.SearchAsync(new(ClientId: Other), [new(Owner)], default));
        Assert.All(await reader.SearchAsync(new(ClientId: Other), [new()], default), entry => Assert.Equal(Other, entry.ClientId));
    }

    [Theory]
    [InlineData(false, false, true)]
    [InlineData(false, true, false)]
    [InlineData(true, false, false)]
    public async Task List_operation_enforces_resolved_access(bool denied, bool requestOther, bool expectedSuccess)
    {
        await using var db = new LoansDbContext(new DbContextOptionsBuilder<LoansDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddLightAuthorization(options =>
        {
            options.MapRole("reader", _ => true).Allow("reader", LoanPermissions.Read, "Own");
            options.Resource<LoanApplicationResource>().Access<LoanAccess>()
                .Map(access => access.ClientId, resource => resource.ClientId)
                .Scope("Own", _ => denied ? null : new LoanAccess(Owner));
        });
        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var operation = new ListLoanApplications(new LoanApplicationReader(db),
            scope.ServiceProvider.GetRequiredService<IAuthorizationService>(),
            scope.ServiceProvider.GetRequiredService<IAccessResolver<LoanApplicationResource, LoanAccess>>());
        var result = await operation.HandleAsync(new ClaimsPrincipal(new ClaimsIdentity([], "test")),
            new(ClientId: requestOther ? Other : Owner), default);
        var succeeded = result switch
        {
            LoanSuccess<LoanApplication[]> => true,
            LoanForbidden => false,
            _ => throw new InvalidOperationException("Unexpected result.")
        };
        Assert.Equal(expectedSuccess, succeeded);
    }

    [Fact]
    public void Access_filter_translates_to_postgres_before_limit()
    {
        using var db = new LoansDbContextFactory().CreateDbContext([]);
        var reader = new LoanApplicationReader(db);
        foreach (var accesses in new LoanAccess[][] { [], [new(Owner)], [new(Owner), new(Other)] })
        {
            var sql = reader.BuildQuery(new(Take: 2), accesses).ToQueryString();
            Assert.Contains("WHERE", sql);
            Assert.True(sql.IndexOf("WHERE", StringComparison.Ordinal) < sql.IndexOf("LIMIT", StringComparison.Ordinal));
        }
    }
}

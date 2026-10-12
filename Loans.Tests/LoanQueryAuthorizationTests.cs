using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using ConfigurableAuthorization;
using Loans.Features.LoanApplications;
using Loans.Features.LoanApplications.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Loans.Tests;

public sealed partial class ApiSecurityTests
{
    [Fact]
    public async Task Search_defaults_to_own_client_and_rejects_explicit_foreign_client()
    {
        using var factory = new ApiFactory();
        using var writer = CreateClient(factory, TechnicalToken("loans.write"));
        var own = await CreateOriginApplication(writer, Owner, "digital");
        await CreateOriginApplication(writer, Other, "digital");
        using var client = CreateClient(factory, Token(Owner.ToString()));
        foreach (var query in new[] { "", $"?clientId={Owner}", "?product=retail-loan&channel=digital" })
        {
            var items = await client.GetFromJsonAsync<LoanApplication[]>("/loan-applications/" + query, JsonOptions);
            Assert.Equal(own.Id, Assert.Single(items!).Id);
        }
        Assert.Equal(HttpStatusCode.Forbidden,
            (await client.GetAsync($"/loan-applications/?clientId={Other}")).StatusCode);
        Assert.Empty((await client.GetFromJsonAsync<LoanApplication[]>(
            "/loan-applications/?product=nonexistent-product", JsonOptions))!);
    }

    [Fact]
    public async Task Search_rejects_conflicting_combinations_without_combining_grants()
    {
        using var factory = new ApiFactory(CorrelatedGrants());
        using var employee = CreateClient(factory, Token(null, null,
            new Claim(ApiSecurity.TokenTypeClaim, "employee"), new Claim("scope", "analyst"),
            new Claim(ApiSecurity.BranchIdClaim, Branch.ToString())));
        foreach (var query in new[] { "product=retail-loan&channel=branch", "product=business-loan&channel=store",
                     $"product=business-loan&branchId={OtherBranch}" })
            Assert.Equal(HttpStatusCode.Forbidden, (await employee.GetAsync("/loan-applications/?" + query)).StatusCode);
        // An allowed search with no matching records is successful.
        Assert.Empty((await employee.GetFromJsonAsync<LoanApplication[]>(
            "/loan-applications/?product=retail-loan&channel=store", JsonOptions))!);
    }

    [Fact]
    public async Task Branch_search_accepts_client_filter_and_restricts_before_pagination()
    {
        using var factory = new ApiFactory();
        using var writer = CreateClient(factory, TechnicalToken("loans.write"));
        var first = await CreateOriginApplication(writer, Owner, "branch", Branch);
        await CreateOriginApplication(writer, Owner, "branch", Branch);
        await CreateOriginApplication(writer, Owner, "branch", OtherBranch);
        await CreateOriginApplication(writer, Other, "branch", Branch);
        using var seller = CreateClient(factory, Token(null, null,
            new Claim(ApiSecurity.TokenTypeClaim, "employee"), new Claim("role", "seller"),
            new Claim(ApiSecurity.BranchIdClaim, Branch.ToString())));
        var items = (await seller.GetFromJsonAsync<LoanApplication[]>(
            $"/loan-applications/?clientId={Owner}&branchId={Branch}&skip=1&take=1", JsonOptions))!;
        Assert.Equal(first.Id, Assert.Single(items).Id);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await seller.GetAsync($"/loan-applications/?branchId={OtherBranch}")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await seller.GetAsync("/loan-applications/?channel=digital")).StatusCode);
    }

    [Theory]
    [InlineData("product=INVALID")]
    [InlineData("channel=unknown")]
    [InlineData("clientId=invalid")]
    [InlineData("branchId=invalid")]
    [InlineData("take=101")]
    public async Task Search_validates_parameters(string query)
    {
        using var factory = new ApiFactory();
        using var client = CreateClient(factory, Token(Owner.ToString()));
        Assert.Equal(HttpStatusCode.BadRequest, (await client.GetAsync("/loan-applications/?" + query)).StatusCode);
    }
}

public sealed class LoanQueryAuthorizationTests
{
    private static readonly ClaimsPrincipal User = new(new ClaimsIdentity([], "test"));

    [Theory]
    [InlineData("All")]
    [InlineData("Own")]
    [InlineData("OwnBranch")]
    public async Task Query_resource_and_collection_authorization_agree(string scopeName)
    {
        using var provider = Provider(scopeName);
        using var scope = provider.CreateScope();
        var services = scope.ServiceProvider;
        var client = Guid.NewGuid();
        var branch = Guid.NewGuid();
        var user = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ApiSecurity.ClientIdClaim, client.ToString()),
            new Claim(ApiSecurity.BranchIdClaim, branch.ToString()),
            new Claim(ApiSecurity.AllowedProductClaim, "retail-loan")], "test"));
        var queryAuthorization = services.GetRequiredService<LoanQueryAuthorization>();
        var query = await queryAuthorization.AuthorizeAsync(user, new(), default);
        Assert.NotNull(query);
        using var db = new LoansDbContext(new DbContextOptionsBuilder<LoansDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);
        var loans = (from owner in new[] { client, Guid.NewGuid() }
                     from office in new Guid?[] { branch, Guid.NewGuid(), null }
                     from channel in new[] { "branch", "digital", "store", null }
                     from product in new[] { "retail-loan", "business-loan", null }
                     select new LoanApplicationEntity
                     {
                         Id = Guid.NewGuid(), ClientId = owner, BranchId = office,
                         Channel = channel, Product = product, ApplicantName = "Test",
                         CreatedAt = DateTimeOffset.UtcNow
                     }).ToArray();
        db.AddRange(loans);
        await db.SaveChangesAsync();
        var expected = new List<Guid>();
        var authorization = services.GetRequiredService<IAuthorizationService>();
        foreach (var loan in loans)
            if ((await authorization.AuthorizeAsync(user, LoanApplicationResource.From(loan),
                    [new PermissionRequirement(LoanPermissions.Read)])).Succeeded)
                expected.Add(loan.Id);
        var filtered = await services.GetRequiredService<ResourceAuthorization<LoanGrantOptions>>()
            .FilterAsync(user, loans, LoanApplicationResource.From, LoanPermissions.Read);
        var results = await new LoanApplicationReader(db).SearchAsync(query with { Filters = new(Take: 100) }, default);
        Assert.NotEmpty(expected);
        Assert.Equal(expected.Order(), filtered.Select(l => l.Id).Order());
        Assert.Equal(expected.Order(), results.Select(l => l.Id).Order());
        Assert.Null(await queryAuthorization.AuthorizeAsync(user, new(Product: "business-loan"), default));
        if (scopeName == "Own")
            Assert.Null(await queryAuthorization.AuthorizeAsync(user, new(ClientId: Guid.NewGuid()), default));
        if (scopeName == "OwnBranch")
            Assert.Null(await queryAuthorization.AuthorizeAsync(user, new(Channel: "digital"), default));
    }

    [Theory]
    [InlineData("Own")]
    [InlineData("OwnBranch")]
    public async Task Unresolved_identity_denies_queries(string scopeName)
    {
        using var provider = Provider(scopeName);
        using var scope = provider.CreateScope();
        Assert.Null(await scope.ServiceProvider.GetRequiredService<LoanQueryAuthorization>()
            .AuthorizeAsync(User, new(), default));
    }

    [Fact]
    public async Task Employee_branch_scope_resolves_once_and_rejects_invalid_branch_claim()
    {
        var branch = Guid.NewGuid();
        var resolver = new TestBranchResolver(branch);
        var scope = new EmployeeBranchScope([resolver]);
        var user = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ApiSecurity.TokenTypeClaim, "employee"), new Claim("employee_id", "x123")], "test"));
        Assert.True(EmployeeBranchScope.CanEvaluate(user));
        var access = await scope.ResolveAsync(user, default);
        Assert.Equal(branch, access!.BranchId);
        Assert.Equal(new[] { LoanChannels.Branch }, access.Channels);
        Assert.True(access.Allows(new LoanApplicationResource(Guid.NewGuid(), branch, null, LoanChannels.Branch)));
        Assert.False(access.Allows(new LoanApplicationResource(Guid.NewGuid(), branch, null, LoanChannels.Digital)));
        Assert.False(access.Allows(new LoanApplicationResource(Guid.NewGuid(), Guid.NewGuid(), null, LoanChannels.Branch)));
        await scope.ResolveAsync(user, default);
        Assert.Equal(1, resolver.Calls);

        var invalid = new ClaimsPrincipal(new ClaimsIdentity(user.Claims.Append(
            new Claim(ApiSecurity.BranchIdClaim, "invalid")), "test"));
        Assert.False(EmployeeBranchScope.CanEvaluate(invalid));
        Assert.Null(await scope.ResolveAsync(invalid, default));
        Assert.Equal(1, resolver.Calls);
    }

    [Fact]
    public async Task Cancellation_is_propagated()
    {
        using var provider = Provider("All");
        using var scope = provider.CreateScope();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            scope.ServiceProvider.GetRequiredService<LoanQueryAuthorization>().AuthorizeAsync(User, new(), new(true)));
    }

    [Fact]
    public void PostgreSql_translates_access_and_search_filters_with_server_side_pagination()
    {
        using var db = new LoansDbContext(new DbContextOptionsBuilder<LoansDbContext>()
            .UseNpgsql("Host=unused;Database=translation").Options);
        var reader = new LoanApplicationReader(db);
        var query = new AuthorizedLoanQuery(new(Skip: 2, Take: 3, ClientId: Guid.NewGuid()),
            [new(Products: ["retail-loan"], Channels: ["store"]),
             new(BranchId: Guid.NewGuid(), Products: ["business-loan"], Channels: ["branch"])]);
        var sql = reader.BuildQuery(query).ToQueryString();
        Assert.Contains("WHERE", sql);
        Assert.Contains(" OR ", sql);
        Assert.Contains("\"ClientId\" =", sql);
        Assert.Contains("\"BranchId\" =", sql);
        Assert.Contains("\"Product\"", sql);
        Assert.Contains("\"Channel\"", sql);
        Assert.Contains("ORDER BY", sql);
        Assert.Contains("LIMIT", sql);
        Assert.Contains("OFFSET", sql);
        Assert.Contains("WHERE FALSE", reader.BuildQuery(new(new(), [])).ToQueryString(), StringComparison.OrdinalIgnoreCase);
    }

    [ReadDatabaseFact]
    public async Task PostgreSql_executes_correlated_grants_and_pages_only_authorized_matches()
    {
        await using var db = new LoansDbContext(new DbContextOptionsBuilder<LoansDbContext>()
            .UseNpgsql(Environment.GetEnvironmentVariable("LOANS_TEST_POSTGRES")).Options);
        await db.Database.OpenConnectionAsync();
        await using var transaction = await db.Database.BeginTransactionAsync();
        // Session-local table, rolled back on disposal; never migrate or clear an existing database.
        await db.Database.ExecuteSqlRawAsync(db.Database.GenerateCreateScript()
            .Replace("CREATE TABLE", "CREATE TEMP TABLE", StringComparison.Ordinal));
        var client = Guid.NewGuid();
        var branch = Guid.NewGuid();
        LoanApplicationEntity Loan(int day, string? product, string channel, Guid? branchId = null, Guid? clientId = null) => new()
        {
            Id = Guid.NewGuid(), ClientId = clientId ?? client, ApplicantName = "Test", Amount = 1000, TermMonths = 12,
            Product = product, Channel = channel, BranchId = branchId,
            CreatedAt = new DateTimeOffset(2026, 1, day, 0, 0, 0, TimeSpan.Zero)
        };
        var store = Loan(1, "retail-loan", "store");
        var branchLoan = Loan(2, "business-loan", "branch", branch);
        db.AddRange(store, branchLoan,
            Loan(3, "retail-loan", "branch", branch),
            Loan(4, "business-loan", "store"),
            Loan(5, "business-loan", "branch", Guid.NewGuid()),
            Loan(6, null, "store"),
            Loan(7, "retail-loan", "store", clientId: Guid.NewGuid()));
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();
        var reader = new LoanApplicationReader(db);
        LoanAccess[] alternatives =
        [
            new(Products: ["retail-loan"], Channels: ["store"]),
            new(BranchId: branch, Products: ["business-loan"], Channels: ["branch"])
        ];
        var all = await reader.SearchAsync(new(new(ClientId: client), alternatives), default);
        Assert.Equal(new[] { branchLoan.Id, store.Id }, all.Select(item => item.Id));
        var page = await reader.SearchAsync(new(new(Skip: 1, Take: 1, ClientId: client), alternatives), default);
        Assert.Equal(store.Id, Assert.Single(page).Id);
        var filtered = await reader.SearchAsync(new(new(ClientId: client, Product: "business-loan",
            BranchId: branch, Channel: "branch"), alternatives), default);
        Assert.Equal(branchLoan.Id, Assert.Single(filtered).Id);
        Assert.Empty(await reader.SearchAsync(new(new(), []), default));
        Assert.Equal(7, (await reader.SearchAsync(new(new(), [new()]), default)).Length);
    }

    private sealed class ReadDatabaseFactAttribute : FactAttribute
    {
        public ReadDatabaseFactAttribute()
        {
            if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("LOANS_TEST_POSTGRES")))
                Skip = "Set LOANS_TEST_POSTGRES to run against PostgreSQL using a transaction and a temporary table.";
        }
    }

    private static ServiceProvider Provider(string scope)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Authorization:ActorRoles:client:0"] = "reader",
            ["Authorization:Roles:reader:Services:loans:Grants:0:Permissions:0"] = LoanPermissions.Read,
            ["Authorization:Roles:reader:Services:loans:Grants:0:Scope"] = scope,
            ["Authorization:Roles:reader:Services:loans:Grants:0:Products:0"] = "retail-loan",
            ["Authorization:Roles:reader:Services:loans:Grants:0:Products:1"] = "business-loan"
        }).Build());
        services.AddLoanAuthorization();
        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
    }

    private sealed class TestBranchResolver(Guid branch) : IEmployeeBranchResolver
    {
        public int Calls { get; private set; }
        public Task<Guid?> ResolveAsync(string employeeId, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult<Guid?>(employeeId == "x123" ? branch : null);
        }
    }
}

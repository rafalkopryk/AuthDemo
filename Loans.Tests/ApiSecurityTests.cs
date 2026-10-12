using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Loans;
using Loans.Features.LoanApplications;
using Loans.Features.LoanApplications.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Loans.Tests;

public sealed partial class ApiSecurityTests
{
    private static readonly Guid Owner = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid Other = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() }
    };
    private static readonly SymmetricSecurityKey SigningKey = new(
        Encoding.UTF8.GetBytes("authdemo-tests-only-signing-key-at-least-32-bytes"));

    [Theory]
    [InlineData("GET", "")]
    [InlineData("POST", "/")]
    [InlineData("PUT", "")]
    [InlineData("POST", "/submit")]
    public async Task All_operations_require_a_token(string method, string suffix)
    {
        using var factory = new ApiFactory();
        using var client = CreateClient(factory);
        var path = method == "POST" && suffix == "/"
            ? "/loan-applications/"
            : $"/loan-applications/{Guid.NewGuid()}{suffix}";
        using var request = new HttpRequestMessage(new HttpMethod(method), path);
        request.Content = JsonContent.Create(Request(Owner));
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(request)).StatusCode);
    }

    [Theory]
    [InlineData("issuer")]
    [InlineData("audience")]
    [InlineData("expired")]
    [InlineData("signature")]
    [InlineData("malformed")]
    public async Task Invalid_tokens_are_rejected(string failure)
    {
        using var factory = new ApiFactory();
        using var client = CreateClient(factory, Token(Owner.ToString(), failure));
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await client.GetAsync($"/loan-applications/{Guid.NewGuid()}")).StatusCode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("not-a-guid")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    public async Task Missing_or_invalid_client_claim_is_forbidden(string? clientId)
    {
        using var factory = new ApiFactory();
        using var client = CreateClient(factory, Token(clientId));
        Assert.Equal(HttpStatusCode.Forbidden,
            (await client.GetAsync($"/loan-applications/{Guid.NewGuid()}")).StatusCode);
    }

    [Fact]
    public async Task Missing_application_returns_not_found_for_authorized_operations()
    {
        using var factory = new ApiFactory();
        using var client = CreateClient(factory, TechnicalToken("loans.read loans.write"));
        var path = $"/loan-applications/{Guid.NewGuid()}";
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync(path)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.PutAsJsonAsync(path, Request(Owner))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.PostAsync(path + "/submit", null)).StatusCode);
    }

    [Fact]
    public async Task Owner_can_create_read_update_and_submit()
    {
        using var factory = new ApiFactory();
        using var client = CreateClient(factory, Token(Owner.ToString()));
        var created = await client.PostAsJsonAsync("/loan-applications/", CreateRequest(Owner));
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var application = (await created.Content.ReadFromJsonAsync<LoanApplication>(JsonOptions))!;
        var path = $"/loan-applications/{application.Id}";
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync(path)).StatusCode);
        var updated = await client.PutAsJsonAsync(path, Request(Owner) with { Amount = 2000 });
        Assert.Equal(HttpStatusCode.NoContent, updated.StatusCode);
        Assert.Empty(await updated.Content.ReadAsByteArrayAsync());

        var submitted = await client.PostAsync(path + "/submit", null);
        Assert.Equal(HttpStatusCode.NoContent, submitted.StatusCode);
        Assert.Empty(await submitted.Content.ReadAsByteArrayAsync());

        var saved = (await (await client.GetAsync(path)).Content.ReadFromJsonAsync<LoanApplication>(JsonOptions))!;
        Assert.Equal(2000, saved.Amount);
        Assert.Equal(LoanApplicationStatus.Submitted, saved.Status);
        Assert.Equal(HttpStatusCode.Conflict,
            (await client.PutAsJsonAsync(path, Request(Owner))).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await client.PostAsync(path + "/submit", null)).StatusCode);
    }

    [Fact]
    public async Task Other_client_cannot_read_update_or_submit_and_does_not_change_data()
    {
        using var factory = new ApiFactory();
        using var owner = CreateClient(factory, Token(Owner.ToString()));
        using var other = CreateClient(factory, Token(Other.ToString()));
        var created = await owner.PostAsJsonAsync("/loan-applications/", CreateRequest(Owner));
        var application = (await created.Content.ReadFromJsonAsync<LoanApplication>(JsonOptions))!;
        var path = $"/loan-applications/{application.Id}";
        Assert.Equal(HttpStatusCode.Forbidden, (await other.GetAsync(path)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await other.PutAsJsonAsync(path, Request(Other) with { Amount = 9000 })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await other.PostAsync(path + "/submit", null)).StatusCode);
        var unchanged = (await owner.GetFromJsonAsync<LoanApplication>(path, JsonOptions))!;
        Assert.Equal(Owner, unchanged.ClientId);
        Assert.Equal(1000m, unchanged.Amount);
        Assert.Equal(LoanApplicationStatus.Draft, unchanged.Status);
    }

    [Fact]
    public async Task Client_cannot_create_for_another_owner_or_transfer_ownership()
    {
        using var factory = new ApiFactory();
        using var client = CreateClient(factory, Token(Owner.ToString()));
        Assert.Equal(HttpStatusCode.Forbidden,
            (await client.PostAsJsonAsync("/loan-applications/", CreateRequest(Other))).StatusCode);
        var created = await client.PostAsJsonAsync("/loan-applications/", CreateRequest(Owner));
        var application = (await created.Content.ReadFromJsonAsync<LoanApplication>(JsonOptions))!;
        // The stored resource is authorized; changing its immutable owner is a domain conflict.
        Assert.Equal(HttpStatusCode.Conflict,
            (await client.PutAsJsonAsync($"/loan-applications/{application.Id}", Request(Other))).StatusCode);
    }

    [Fact]
    public async Task Development_health_and_openapi_remain_public_and_describe_bearer_auth()
    {
        using var factory = new ApiFactory();
        using var client = CreateClient(factory);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/alive")).StatusCode);
        var document = await client.GetStringAsync("/openapi/v1.json");
        Assert.Contains("bearer", document);
        Assert.Contains("securitySchemes", document);
    }

    [Fact]
    public async Task Technical_reader_can_read_multiple_clients_and_cannot_write_even_with_client_id()
    {
        using var factory = new ApiFactory();
        using var owner = CreateClient(factory, Token(Owner.ToString()));
        using var other = CreateClient(factory, Token(Other.ToString()));
        using var reader = CreateClient(factory, TechnicalToken("loans.read", Owner.ToString()));
        foreach (var pair in new[] { (Client: owner, Id: Owner), (Client: other, Id: Other) })
        {
            var created = await pair.Client.PostAsJsonAsync("/loan-applications/", CreateRequest(pair.Id));
            var application = (await created.Content.ReadFromJsonAsync<LoanApplication>(JsonOptions))!;
            var path = $"/loan-applications/{application.Id}";
            Assert.Equal(HttpStatusCode.OK, (await reader.GetAsync(path)).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden,
                (await reader.PutAsJsonAsync(path, Request(pair.Id) with { Amount = 9000 })).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await reader.PostAsync(path + "/submit", null)).StatusCode);
            var unchanged = (await pair.Client.GetFromJsonAsync<LoanApplication>(path, JsonOptions))!;
            Assert.Equal(1000m, unchanged.Amount);
            Assert.Equal(LoanApplicationStatus.Draft, unchanged.Status);
        }
        Assert.Equal(HttpStatusCode.Forbidden,
            (await reader.PostAsJsonAsync("/loan-applications/", CreateRequest(Owner))).StatusCode);
    }

    [Theory]
    [InlineData("")]
    [InlineData("payments.read")]
    [InlineData("loans.read.extra")]
    [InlineData("LOANS.READ")]
    public async Task Technical_token_without_exact_api_scope_is_forbidden(string scope)
    {
        using var factory = new ApiFactory();
        using var technical = CreateClient(factory, TechnicalToken(scope, Owner.ToString()));
        Assert.Equal(HttpStatusCode.Forbidden,
            (await technical.GetAsync($"/loan-applications/{Guid.NewGuid()}")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await technical.PostAsJsonAsync("/loan-applications/", CreateRequest(Owner))).StatusCode);
    }

    [Theory]
    [InlineData("loans.read loans.write", false)]
    [InlineData("loans.read", true)]
    public async Task Technical_scopes_support_space_separated_and_repeated_claims(string scope, bool repeated)
    {
        using var factory = new ApiFactory();
        var claims = new List<Claim> { new(ApiSecurity.TokenTypeClaim, "technical"), new("scope", scope) };
        if (repeated) claims.Add(new Claim("scope", "loans.write"));
        using var technical = CreateClient(factory, Token(null, null, claims.ToArray()));
        var created = await technical.PostAsJsonAsync("/loan-applications/", CreateRequest(Other));
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var application = (await created.Content.ReadFromJsonAsync<LoanApplication>(JsonOptions))!;
        var path = $"/loan-applications/{application.Id}";
        Assert.Equal(HttpStatusCode.OK, (await technical.GetAsync(path)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent,
            (await technical.PutAsJsonAsync(path, Request(Other) with { Amount = 2000 })).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict,
            (await technical.PutAsJsonAsync(path, Request(Owner))).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await technical.PostAsync(path + "/submit", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict,
            (await technical.PutAsJsonAsync(path, Request(Other))).StatusCode);
    }

    [Fact]
    public async Task Technical_writer_can_update_another_clients_application_but_cannot_read()
    {
        using var factory = new ApiFactory();
        using var owner = CreateClient(factory, Token(Owner.ToString()));
        using var writer = CreateClient(factory, TechnicalToken("loans.write"));
        var created = await owner.PostAsJsonAsync("/loan-applications/", CreateRequest(Owner));
        var application = (await created.Content.ReadFromJsonAsync<LoanApplication>(JsonOptions))!;
        var path = $"/loan-applications/{application.Id}";
        Assert.Equal(HttpStatusCode.Forbidden, (await writer.GetAsync(path)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent,
            (await writer.PutAsJsonAsync(path, Request(Owner) with { Amount = 3000 })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await writer.PostAsync(path + "/submit", null)).StatusCode);
        var updated = (await owner.GetFromJsonAsync<LoanApplication>(path, JsonOptions))!;
        Assert.Equal(3000m, updated.Amount);
        Assert.Equal(Owner, updated.ClientId);
        Assert.Equal(LoanApplicationStatus.Submitted, updated.Status);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("client")]
    public async Task Client_scopes_do_not_grant_global_access(string? tokenType)
    {
        using var factory = new ApiFactory();
        using var other = CreateClient(factory, Token(Other.ToString()));
        var claims = new List<Claim> { new("scope", "loans.read loans.write") };
        if (tokenType is not null) claims.Add(new Claim(ApiSecurity.TokenTypeClaim, tokenType));
        using var client = CreateClient(factory, Token(Owner.ToString(), null, claims.ToArray()));
        var created = await other.PostAsJsonAsync("/loan-applications/", CreateRequest(Other));
        var application = (await created.Content.ReadFromJsonAsync<LoanApplication>(JsonOptions))!;
        var path = $"/loan-applications/{application.Id}";
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync(path)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await client.PutAsJsonAsync(path, Request(Owner))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsync(path + "/submit", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await client.PostAsJsonAsync("/loan-applications/", CreateRequest(Other))).StatusCode);
    }

    [Theory]
    [InlineData("unknown", false)]
    [InlineData("technical", true)]
    public async Task Unknown_or_ambiguous_token_type_cannot_fall_back_to_client_access(string type, bool duplicate)
    {
        using var factory = new ApiFactory();
        var claims = new List<Claim> { new(ApiSecurity.TokenTypeClaim, type), new("scope", "loans.read loans.write") };
        if (duplicate) claims.Add(new Claim(ApiSecurity.TokenTypeClaim, "client"));
        using var client = CreateClient(factory, Token(Owner.ToString(), null, claims.ToArray()));
        Assert.Equal(HttpStatusCode.Forbidden,
            (await client.GetAsync($"/loan-applications/{Guid.NewGuid()}")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await client.PostAsJsonAsync("/loan-applications/", CreateRequest(Owner))).StatusCode);
    }

    [Theory]
    [InlineData("?skip=-1")]
    [InlineData("?take=0")]
    [InlineData("?take=101")]
    public async Task Invalid_pagination_is_rejected(string query)
    {
        using var factory = new ApiFactory();
        using var reader = CreateClient(factory, TechnicalToken("loans.read"));
        Assert.Equal(HttpStatusCode.BadRequest, (await reader.GetAsync("/loan-applications/" + query)).StatusCode);
    }

    [Fact]
    public void Product_migration_matches_model_and_adds_nullable_column()
    {
        using var db = new LoansDbContextFactory().CreateDbContext([]);
        Assert.False(db.Database.HasPendingModelChanges());
        var script = db.GetService<IMigrator>().GenerateScript("20261010190000_InitialCreate", "20261010193000_AddLoanProduct");
        Assert.Contains("ADD \"Product\" character varying(64)", script);
        Assert.DoesNotContain("NOT NULL", script);
    }

    [Theory]
    [InlineData("branch", null)]
    [InlineData("branch", "00000000-0000-0000-0000-000000000000")]
    [InlineData("digital", "33333333-3333-3333-3333-333333333333")]
    [InlineData("store", "33333333-3333-3333-3333-333333333333")]
    [InlineData("invalid", null)]
    public async Task Invalid_request_origin_is_rejected(string channel, string? branchId)
    {
        using var factory = new ApiFactory();
        using var writer = CreateClient(factory, TechnicalToken("loans.write"));
        Assert.Equal(HttpStatusCode.BadRequest,
            (await writer.PostAsJsonAsync("/loan-applications/", CreateRequest(Owner) with
            { Channel = channel, BranchId = branchId is null ? null : Guid.Parse(branchId) })).StatusCode);
    }

    [Fact]
    public void Origin_migration_matches_model_and_preserves_unknown_origins()
    {
        using var db = new LoansDbContextFactory().CreateDbContext([]);
        Assert.False(db.Database.HasPendingModelChanges());
        var script = db.GetService<IMigrator>().GenerateScript("20261010193000_AddLoanProduct", "20261010200000_AddLoanOrigin");
        Assert.Contains("ADD \"Channel\" character varying(16)", script);
        Assert.Contains("ADD \"BranchId\" uuid", script);
        Assert.DoesNotContain("NOT NULL", script);
        Assert.DoesNotContain("UPDATE", script);
    }

    [Fact]
    public void Empty_union_result_cannot_be_mapped_to_a_success_response()
    {
        Assert.Throws<InvalidOperationException>(() =>
            default(LoanApplicationResult<LoanApplication>).ToHttpResult());
    }

    private static string TechnicalToken(string scope, string? clientId = null) =>
        Token(clientId, null, new Claim(ApiSecurity.TokenTypeClaim, "technical"), new Claim("scope", scope));

    private static LoanApplicationRequest Request(Guid clientId) => new(clientId, "Jan Kowalski", 1000, 12, null);

    private static LoanApplicationRequest CreateRequest(Guid clientId) =>
        Request(clientId) with { Channel = LoanChannels.Digital };

    private static HttpClient CreateClient(ApiFactory factory, string? token = null)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost") });
        if (token is not null)
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    private static string Token(string? clientId, string? failure = null, params Claim[] additionalClaims)
    {
        if (failure == "malformed") return "not-a-jwt";
        var key = failure == "signature"
            ? new SymmetricSecurityKey(Encoding.UTF8.GetBytes("another-test-signing-key-at-least-32-bytes"))
            : SigningKey;
        var token = new JwtSecurityToken(
            issuer: failure == "issuer" ? "untrusted" : "authdemo-tests",
            audience: failure == "audience" ? "another-api" : "loans-api",
            claims: (clientId is null ? Array.Empty<Claim>() : [new Claim(ApiSecurity.ClientIdClaim, clientId)]).Concat(additionalClaims),
            notBefore: DateTime.UtcNow.AddMinutes(-10),
            expires: failure == "expired" ? DateTime.UtcNow.AddMinutes(-5) : DateTime.UtcNow.AddMinutes(5),
            signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256));
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private sealed class ApiFactory : WebApplicationFactory<Program>
    {
        private readonly string database = Guid.NewGuid().ToString();

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(
                new Dictionary<string, string?>
                {
                    ["ConnectionStrings:loansdb"] = "Host=unused;Database=tests",
                    ["Authentication:Schemes:Bearer:ValidIssuer"] = "authdemo-tests",
                    ["Authentication:Schemes:Bearer:ValidIssuers:0"] = "authdemo-tests",
                    ["Authentication:Schemes:Bearer:ValidAudiences:0"] = "loans-api",
                    ["Authentication:Schemes:Bearer:SigningKeys:0:Issuer"] = "authdemo-tests",
                    ["Authentication:Schemes:Bearer:SigningKeys:0:Value"] = Convert.ToBase64String(SigningKey.Key),
                    ["Authentication:Schemes:Bearer:SigningKeys:0:Length"] = SigningKey.Key.Length.ToString()
                }));
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<DbContextOptions<LoansDbContext>>();
                services.RemoveAll<IDbContextOptionsConfiguration<LoansDbContext>>();
                services.AddDbContext<LoansDbContext>(options => options.UseInMemoryDatabase(database));
            });
        }
    }
}

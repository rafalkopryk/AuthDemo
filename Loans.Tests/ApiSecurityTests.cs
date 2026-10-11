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

    [Fact]
    public async Task Retail_reader_lists_only_retail_loans_across_clients_and_cannot_read_other_ids()
    {
        using var factory = new ApiFactory();
        using var writer = CreateClient(factory, TechnicalToken("loans.write"));
        var retail1 = await CreateApplication(writer, Owner, "retail-loan");
        var retail2 = await CreateApplication(writer, Other, "retail-loan");
        var business = await CreateApplication(writer, Owner, "business-loan");
        var unassigned = await CreateApplication(writer, Other, null);
        using var reader = CreateClient(factory, ProductToken("loans.read", "retail-loan"));
        var list = (await reader.GetFromJsonAsync<LoanApplication[]>("/loan-applications/", JsonOptions))!;
        Assert.Equal(2, list.Length);
        Assert.All(list, item => Assert.Equal("retail-loan", item.Product));
        foreach (var id in new[] { retail1.Id, retail2.Id })
            Assert.Equal(HttpStatusCode.OK, (await reader.GetAsync($"/loan-applications/{id}")).StatusCode);
        foreach (var id in new[] { business.Id, unassigned.Id })
            Assert.Equal(HttpStatusCode.Forbidden, (await reader.GetAsync($"/loan-applications/{id}")).StatusCode);
        var page = (await reader.GetFromJsonAsync<LoanApplication[]>("/loan-applications/?take=1", JsonOptions))!;
        Assert.Single(page);
        Assert.Equal("retail-loan", page[0].Product);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await reader.PostAsJsonAsync("/loan-applications/", CreateRequest(Owner) with { Product = "retail-loan" })).StatusCode);
    }

    [Fact]
    public async Task Product_restriction_also_applies_to_writes_and_product_cannot_be_changed()
    {
        using var factory = new ApiFactory();
        using var unrestricted = CreateClient(factory, TechnicalToken("loans.read loans.write"));
        var business = await CreateApplication(unrestricted, Owner, "business-loan");
        var unassigned = await CreateApplication(unrestricted, Owner, null);
        using var retail = CreateClient(factory, ProductToken("loans.read loans.write", "retail-loan"));
        foreach (var product in new string?[] { "business-loan", null })
            Assert.Equal(HttpStatusCode.Forbidden,
                (await retail.PostAsJsonAsync("/loan-applications/", CreateRequest(Owner) with { Product = product })).StatusCode);
        foreach (var id in new[] { business.Id, unassigned.Id })
        {
            Assert.Equal(HttpStatusCode.Forbidden,
                (await retail.PutAsJsonAsync($"/loan-applications/{id}", Request(Owner) with { Product = "retail-loan" })).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden,
                (await retail.PostAsync($"/loan-applications/{id}/submit", null)).StatusCode);
        }
        var application = await CreateApplication(retail, Other, "retail-loan");
        var path = $"/loan-applications/{application.Id}";
        Assert.Equal(HttpStatusCode.NoContent,
            (await retail.PutAsJsonAsync(path, Request(Other) with { Product = "retail-loan", Amount = 2000 })).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict,
            (await unrestricted.PutAsJsonAsync(path, Request(Other) with { Product = "business-loan" })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await retail.PostAsync(path + "/submit", null)).StatusCode);
        var unchanged = (await unrestricted.GetFromJsonAsync<LoanApplication>($"/loan-applications/{business.Id}", JsonOptions))!;
        Assert.Equal("business-loan", unchanged.Product);
        Assert.Equal(LoanApplicationStatus.Draft, unchanged.Status);
    }

    [Fact]
    public async Task Client_and_product_filters_are_combined_and_global_reader_remains_unrestricted()
    {
        using var factory = new ApiFactory();
        using var writer = CreateClient(factory, TechnicalToken("loans.write"));
        var ownRetail = await CreateApplication(writer, Owner, "retail-loan");
        var otherRetail = await CreateApplication(writer, Other, "retail-loan");
        var ownBusiness = await CreateApplication(writer, Owner, "business-loan");
        await CreateApplication(writer, Owner, null);
        using var client = CreateClient(factory, Token(Owner.ToString(), null,
            new Claim(ApiSecurity.AllowedProductClaim, "retail-loan")));
        var list = (await client.GetFromJsonAsync<LoanApplication[]>("/loan-applications/", JsonOptions))!;
        Assert.Equal(ownRetail.Id, Assert.Single(list).Id);
        foreach (var id in new[] { otherRetail.Id, ownBusiness.Id })
            Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync($"/loan-applications/{id}")).StatusCode);
        using var globalReader = CreateClient(factory, TechnicalToken("loans.read"));
        Assert.Equal(4, (await globalReader.GetFromJsonAsync<LoanApplication[]>("/loan-applications/", JsonOptions))!.Length);
        using var normalClient = CreateClient(factory, Token(Other.ToString()));
        Assert.Equal(otherRetail.Id, Assert.Single(
            (await normalClient.GetFromJsonAsync<LoanApplication[]>("/loan-applications/", JsonOptions))!).Id);
    }

    [Fact]
    public async Task Multiple_product_claims_allow_union_of_exact_product_codes()
    {
        using var factory = new ApiFactory();
        using var writer = CreateClient(factory, TechnicalToken("loans.write"));
        await CreateApplication(writer, Owner, "retail-loan");
        await CreateApplication(writer, Other, "business-loan");
        await CreateApplication(writer, Other, "retail-loan-extra");
        using var reader = CreateClient(factory, Token(null, null,
            new Claim(ApiSecurity.TokenTypeClaim, "technical"), new Claim("scope", "loans.read"),
            new Claim(ApiSecurity.AllowedProductClaim, "retail-loan"),
            new Claim(ApiSecurity.AllowedProductClaim, "business-loan")));
        var list = (await reader.GetFromJsonAsync<LoanApplication[]>("/loan-applications/", JsonOptions))!;
        Assert.Equal(2, list.Length);
        Assert.DoesNotContain(list, item => item.Product == "retail-loan-extra");
    }

    [Theory]
    [InlineData("")]
    [InlineData("*")]
    [InlineData("Retail-Loan")]
    [InlineData("retail-loan business-loan")]
    public async Task Invalid_product_claims_do_not_grant_unrestricted_access(string product)
    {
        using var factory = new ApiFactory();
        using var reader = CreateClient(factory, ProductToken("loans.read", product));
        Assert.Equal(HttpStatusCode.Forbidden, (await reader.GetAsync("/loan-applications/")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await reader.GetAsync($"/loan-applications/{Guid.NewGuid()}")).StatusCode);
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

    private static readonly Guid Branch = Guid.Parse("33333333-3333-3333-3333-333333333333");
    private static readonly Guid OtherBranch = Guid.Parse("44444444-4444-4444-4444-444444444444");
    private static readonly Guid Employee = Guid.Parse("55555555-5555-5555-5555-555555555555");

    [Fact]
    public async Task Employee_branch_scope_can_resolve_missing_branch_from_employee_id()
    {
        var resolver = new TestEmployeeBranchResolver(Employee.ToString(), Branch);
        using var factory = new ApiFactory(branchResolver: resolver);
        using var writer = CreateClient(factory, TechnicalToken("loans.write"));
        var visible = await CreateOriginApplication(writer, Owner, "branch", Branch);
        var otherBranch = await CreateOriginApplication(writer, Owner, "branch", OtherBranch);
        var digital = await CreateOriginApplication(writer, Owner, "digital");

        using var employee = CreateClient(factory, Token(null, null,
            new Claim(ApiSecurity.TokenTypeClaim, "employee"), new Claim("role", "seller"),
            new Claim("employee_id", Employee.ToString())));
        var list = (await employee.GetFromJsonAsync<LoanApplication[]>("/loan-applications/", JsonOptions))!;
        Assert.Equal(visible.Id, Assert.Single(list).Id);
        Assert.Equal(1, resolver.Calls); // One lookup for the whole list.
        Assert.Equal(HttpStatusCode.OK,
            (await employee.GetAsync($"/loan-applications/{visible.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await employee.GetAsync($"/loan-applications/{otherBranch.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await employee.GetAsync($"/loan-applications/{digital.Id}")).StatusCode);

        var calls = resolver.Calls;
        using var invalidBranch = CreateClient(factory, Token(null, null,
            new Claim(ApiSecurity.TokenTypeClaim, "employee"), new Claim("role", "seller"),
            new Claim("employee_id", Employee.ToString()), new Claim(ApiSecurity.BranchIdClaim, "invalid")));
        Assert.Equal(HttpStatusCode.Forbidden,
            (await invalidBranch.GetAsync($"/loan-applications/{visible.Id}")).StatusCode);
        Assert.Equal(calls, resolver.Calls);

        using var unknownEmployee = CreateClient(factory, Token(null, null,
            new Claim(ApiSecurity.TokenTypeClaim, "employee"), new Claim("role", "seller"),
            new Claim("employee_id", Guid.NewGuid().ToString())));
        Assert.Equal(HttpStatusCode.Forbidden,
            (await unknownEmployee.GetAsync($"/loan-applications/{visible.Id}")).StatusCode);
    }

    [Fact]
    public async Task Seller_sees_only_applications_created_in_their_branch_and_not_digital_or_store()
    {
        using var factory = new ApiFactory();
        using var writer = CreateClient(factory, TechnicalToken("loans.write"));
        var ownBranch1 = await CreateOriginApplication(writer, Owner, "branch", Branch);
        var ownBranch2 = await CreateOriginApplication(writer, Other, "branch", Branch);
        var otherBranch = await CreateOriginApplication(writer, Owner, "branch", OtherBranch);
        var digital = await CreateOriginApplication(writer, Owner, "digital");
        var store = await CreateOriginApplication(writer, Owner, "store");
        var unknown = await CreateApplication(writer, Owner, "retail-loan");
        // Verify that legacy inconsistent data with branch_id still cannot expose a digital application.
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<LoansDbContext>();
            var entity = await db.LoanApplications.SingleAsync(item => item.Id == digital.Id);
            entity.BranchId = Branch;
            await db.SaveChangesAsync();
        }
        using var seller = CreateClient(factory, EmployeeToken(Branch.ToString()));
        var list = (await seller.GetFromJsonAsync<LoanApplication[]>("/loan-applications/", JsonOptions))!;
        Assert.Equal(2, list.Length);
        Assert.All(list, item => { Assert.Equal("branch", item.Channel); Assert.Equal(Branch, item.BranchId); });
        foreach (var id in new[] { ownBranch1.Id, ownBranch2.Id })
            Assert.Equal(HttpStatusCode.OK, (await seller.GetAsync($"/loan-applications/{id}")).StatusCode);
        foreach (var id in new[] { otherBranch.Id, digital.Id, store.Id, unknown.Id })
            Assert.Equal(HttpStatusCode.Forbidden, (await seller.GetAsync($"/loan-applications/{id}")).StatusCode);
        var page = (await seller.GetFromJsonAsync<LoanApplication[]>("/loan-applications/?skip=1&take=1", JsonOptions))!;
        Assert.Single(page);
        Assert.Equal(Branch, page[0].BranchId);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await seller.PostAsJsonAsync("/loan-applications/", CreateRequest(Owner) with { Channel = "branch", BranchId = Branch })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await seller.PutAsJsonAsync($"/loan-applications/{ownBranch1.Id}", Request(Owner))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await seller.PostAsync($"/loan-applications/{ownBranch1.Id}/submit", null)).StatusCode);
    }

    [Theory]
    [InlineData(null, "seller", false)]
    [InlineData("invalid", "seller", false)]
    [InlineData("00000000-0000-0000-0000-000000000000", "seller", false)]
    [InlineData("33333333-3333-3333-3333-333333333333", "auditor", false)]
    [InlineData("33333333-3333-3333-3333-333333333333", "seller", true)]
    public async Task Employee_without_valid_role_and_single_branch_cannot_fall_back_to_client_or_technical_access(
        string? branchId, string role, bool duplicateBranch)
    {
        using var factory = new ApiFactory();
        var claims = new List<Claim>
        {
            new(ApiSecurity.TokenTypeClaim, "employee"), new("role", role), new("scope", "loans.read loans.write")
        };
        if (branchId is not null) claims.Add(new Claim(ApiSecurity.BranchIdClaim, branchId));
        if (duplicateBranch) claims.Add(new Claim(ApiSecurity.BranchIdClaim, OtherBranch.ToString()));
        using var employee = CreateClient(factory, Token(Owner.ToString(), null, claims.ToArray()));
        Assert.Equal(HttpStatusCode.Forbidden, (await employee.GetAsync("/loan-applications/")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await employee.PostAsJsonAsync("/loan-applications/", CreateRequest(Owner))).StatusCode);
    }

    [Fact]
    public async Task Employee_with_multiple_roles_and_client_id_keeps_branch_filter_and_cannot_write()
    {
        using var factory = new ApiFactory();
        using var writer = CreateClient(factory, TechnicalToken("loans.write"));
        var visible = await CreateOriginApplication(writer, Other, "branch", Branch);
        await CreateOriginApplication(writer, Owner, "branch", OtherBranch);
        using var employee = CreateClient(factory, Token(Owner.ToString(), null,
            new Claim(ApiSecurity.TokenTypeClaim, "employee"), new Claim("role", "auditor"),
            new Claim("role", "seller"), new Claim(ApiSecurity.BranchIdClaim, Branch.ToString()),
            new Claim("scope", "loans.read loans.write")));
        var list = (await employee.GetFromJsonAsync<LoanApplication[]>("/loan-applications/", JsonOptions))!;
        Assert.Equal(visible.Id, Assert.Single(list).Id);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await employee.PostAsync($"/loan-applications/{visible.Id}/submit", null)).StatusCode);
    }

    [Fact]
    public async Task Store_reader_requires_both_retail_product_and_store_channel()
    {
        using var factory = new ApiFactory();
        using var writer = CreateClient(factory, TechnicalToken("loans.write"));
        var storeRetail = await CreateOriginApplication(writer, Owner, "store");
        var branchRetail = await CreateOriginApplication(writer, Owner, "branch", Branch);
        var digitalRetail = await CreateOriginApplication(writer, Owner, "digital");
        var storeBusiness = await CreateOriginApplication(writer, Other, "store", product: "business-loan");
        var unknown = await CreateApplication(writer, Owner, "retail-loan");
        using var reader = CreateClient(factory, StoreToken("loans.read"));
        var list = (await reader.GetFromJsonAsync<LoanApplication[]>("/loan-applications/", JsonOptions))!;
        Assert.Equal(storeRetail.Id, Assert.Single(list).Id);
        Assert.Equal(HttpStatusCode.OK, (await reader.GetAsync($"/loan-applications/{storeRetail.Id}")).StatusCode);
        foreach (var id in new[] { branchRetail.Id, digitalRetail.Id, storeBusiness.Id, unknown.Id })
            Assert.Equal(HttpStatusCode.Forbidden, (await reader.GetAsync($"/loan-applications/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await reader.PostAsJsonAsync("/loan-applications/", CreateRequest(Owner) with { Product = "retail-loan", Channel = "store" })).StatusCode);
    }

    [Fact]
    public async Task Origin_restriction_applies_to_writes_and_existing_origin_cannot_be_changed()
    {
        using var factory = new ApiFactory();
        using var global = CreateClient(factory, TechnicalToken("loans.read loans.write"));
        var branchRetail = await CreateOriginApplication(global, Owner, "branch", Branch);
        using var store = CreateClient(factory, StoreToken("loans.read loans.write"));
        Assert.Equal(HttpStatusCode.Forbidden,
            (await store.PostAsJsonAsync("/loan-applications/", CreateRequest(Owner) with { Product = "retail-loan", Channel = "digital" })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await store.PutAsJsonAsync($"/loan-applications/{branchRetail.Id}", Request(Owner) with { Product = "retail-loan", Channel = "store" })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await store.PostAsync($"/loan-applications/{branchRetail.Id}/submit", null)).StatusCode);
        var created = await CreateOriginApplication(store, Other, "store");
        Assert.Equal(HttpStatusCode.Conflict,
            (await global.PutAsJsonAsync($"/loan-applications/{created.Id}", Request(Other) with { Product = "retail-loan", Channel = "branch", BranchId = Branch })).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict,
            (await global.PutAsJsonAsync($"/loan-applications/{branchRetail.Id}", Request(Owner) with { Product = "retail-loan", Channel = "branch", BranchId = OtherBranch })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent,
            (await store.PutAsJsonAsync($"/loan-applications/{created.Id}", Request(Other) with { Product = "retail-loan", Amount = 2000 })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await store.PostAsync($"/loan-applications/{created.Id}/submit", null)).StatusCode);
    }

    [Theory]
    [InlineData("branch")]
    [InlineData("store")]
    public async Task Client_cannot_forge_branch_or_store_origin(string channel)
    {
        using var factory = new ApiFactory();
        using var client = CreateClient(factory, Token(Owner.ToString()));
        Assert.Equal(HttpStatusCode.Forbidden,
            (await client.PostAsJsonAsync("/loan-applications/", CreateRequest(Owner) with { Channel = channel, BranchId = channel == "branch" ? Branch : null })).StatusCode);
        var created = await client.PostAsJsonAsync("/loan-applications/", CreateRequest(Owner));
        Assert.Equal("digital", (await created.Content.ReadFromJsonAsync<LoanApplication>(JsonOptions))!.Channel);
    }

    [Theory]
    [InlineData("")]
    [InlineData("*")]
    [InlineData("Store")]
    [InlineData("branch store")]
    public async Task Invalid_channel_claim_is_forbidden(string channel)
    {
        using var factory = new ApiFactory();
        using var client = CreateClient(factory, Token(null, null,
            new Claim(ApiSecurity.TokenTypeClaim, "technical"), new Claim("scope", "loans.read"),
            new Claim(ApiSecurity.AllowedChannelClaim, channel)));
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/loan-applications/")).StatusCode);
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

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Operator_reads_and_edits_branch_drafts_but_cannot_create_or_submit(bool additionalSellerAndScopes)
    {
        using var factory = new ApiFactory();
        using var global = CreateClient(factory, TechnicalToken("loans.read loans.write"));
        var draft = await CreateOriginApplication(global, Other, "branch", Branch);
        var claims = new List<Claim>
        {
            new(ApiSecurity.TokenTypeClaim, "employee"), new("role", "operator"),
            new(ApiSecurity.BranchIdClaim, Branch.ToString())
        };
        if (additionalSellerAndScopes)
        {
            claims.Add(new Claim("role", "seller"));
            claims.Add(new Claim("scope", "loans.read loans.write"));
        }
        using var employee = CreateClient(factory, Token(Owner.ToString(), null, claims.ToArray()));
        var path = $"/loan-applications/{draft.Id}";
        Assert.Equal(HttpStatusCode.OK, (await employee.GetAsync(path)).StatusCode);
        Assert.Equal(draft.Id, Assert.Single(
            (await employee.GetFromJsonAsync<LoanApplication[]>("/loan-applications/", JsonOptions))!).Id);
        Assert.Equal(HttpStatusCode.NoContent,
            (await employee.PutAsJsonAsync(path, Request(Other) with { Product = "retail-loan", Amount = 2500 })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await employee.PostAsJsonAsync("/loan-applications/", CreateRequest(Other) with { Channel = "branch", BranchId = Branch })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await employee.PostAsync(path + "/submit", null)).StatusCode);
        var updated = (await global.GetFromJsonAsync<LoanApplication>(path, JsonOptions))!;
        Assert.Equal(2500m, updated.Amount);
        Assert.Equal(Other, updated.ClientId);
        Assert.Equal(LoanApplicationStatus.Draft, updated.Status);
        Assert.Equal("branch", updated.Channel);
        Assert.Equal(Branch, updated.BranchId);
        Assert.Equal(HttpStatusCode.NoContent, (await global.PostAsync(path + "/submit", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict,
            (await employee.PutAsJsonAsync(path, Request(Other) with { Product = "retail-loan" })).StatusCode);
    }

    [Theory]
    [InlineData("operator")]
    [InlineData("branch_advisor")]
    public async Task Employee_role_cannot_operate_in_other_branches_or_other_channels(string role)
    {
        using var factory = new ApiFactory();
        using var global = CreateClient(factory, TechnicalToken("loans.read loans.write"));
        var excluded = new[]
        {
            await CreateOriginApplication(global, Owner, "branch", OtherBranch),
            await CreateOriginApplication(global, Owner, "digital"),
            await CreateOriginApplication(global, Owner, "store")
        };
        using var employee = CreateClient(factory, EmployeeToken(Branch.ToString(), role));
        Assert.Empty((await employee.GetFromJsonAsync<LoanApplication[]>("/loan-applications/", JsonOptions))!);
        foreach (var item in excluded)
        {
            var path = $"/loan-applications/{item.Id}";
            Assert.Equal(HttpStatusCode.Forbidden, (await employee.GetAsync(path)).StatusCode);
            if (role == "operator")
                Assert.Equal(HttpStatusCode.Forbidden,
                    (await employee.PutAsJsonAsync(path, Request(Owner) with { Product = "retail-loan" })).StatusCode);
            else
                Assert.Equal(HttpStatusCode.Forbidden, (await employee.PostAsync(path + "/submit", null)).StatusCode);
            var unchanged = (await global.GetFromJsonAsync<LoanApplication>(path, JsonOptions))!;
            Assert.Equal(LoanApplicationStatus.Draft, unchanged.Status);
            Assert.Equal(1000m, unchanged.Amount);
        }
    }

    [Fact]
    public async Task Branch_advisor_creates_for_clients_and_submits_only_in_their_branch()
    {
        using var factory = new ApiFactory();
        using var advisor = CreateClient(factory, EmployeeToken(Branch.ToString(), "branch_advisor"));
        foreach (var clientId in new[] { Owner, Other })
        {
            var created = await advisor.PostAsJsonAsync("/loan-applications/", CreateRequest(clientId) with { Product = "retail-loan", Channel = LoanChannels.Branch, BranchId = Branch });
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
            var application = (await created.Content.ReadFromJsonAsync<LoanApplication>(JsonOptions))!;
            Assert.Equal(clientId, application.ClientId);
            Assert.Equal("branch", application.Channel);
            Assert.Equal(Branch, application.BranchId);
            var path = $"/loan-applications/{application.Id}";
            Assert.Equal(HttpStatusCode.OK, (await advisor.GetAsync(path)).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden,
                (await advisor.PutAsJsonAsync(path, Request(clientId) with { Product = "retail-loan" })).StatusCode);
            Assert.Equal(HttpStatusCode.NoContent, (await advisor.PostAsync(path + "/submit", null)).StatusCode);
            Assert.Equal(HttpStatusCode.Conflict, (await advisor.PostAsync(path + "/submit", null)).StatusCode);
            using var client = CreateClient(factory, Token(clientId.ToString()));
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync(path)).StatusCode);
        }
    }

    [Theory]
    [InlineData("digital", false)]
    [InlineData("store", false)]
    [InlineData("branch", true)]
    public async Task Branch_advisor_cannot_create_in_another_channel_or_branch(string channel, bool otherBranch)
    {
        using var factory = new ApiFactory();
        using var employee = CreateClient(factory, EmployeeToken(Branch.ToString(), "branch_advisor"));
        Assert.Equal(HttpStatusCode.Forbidden,
            (await employee.PostAsJsonAsync("/loan-applications/", CreateRequest(Other) with
            { Channel = channel, BranchId = channel == "branch" ? otherBranch ? OtherBranch : Branch : null })).StatusCode);
        Assert.Empty((await employee.GetFromJsonAsync<LoanApplication[]>("/loan-applications/", JsonOptions))!);
    }

    [Fact]
    public async Task Employee_role_permissions_combine_without_losing_branch_restrictions()
    {
        using var factory = new ApiFactory();
        using var employee = CreateClient(factory, Token(null, null,
            new Claim(ApiSecurity.TokenTypeClaim, "employee"), new Claim("role", "operator"),
            new Claim("role", "branch_advisor"), new Claim(ApiSecurity.BranchIdClaim, Branch.ToString())));
        var created = await CreateOriginApplication(employee, Owner, "branch", Branch);
        var path = $"/loan-applications/{created.Id}";
        Assert.Equal(HttpStatusCode.NoContent,
            (await employee.PutAsJsonAsync(path, Request(Owner) with { Product = "retail-loan", Amount = 3500 })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await employee.PostAsync(path + "/submit", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await employee.PostAsJsonAsync("/loan-applications/", CreateRequest(Owner) with { Channel = "digital" })).StatusCode);
    }

    [Theory]
    [InlineData("operator", "edit")]
    [InlineData("branch_advisor", "submit")]
    public async Task Employee_product_restriction_also_limits_new_role_operations(string role, string operation)
    {
        using var factory = new ApiFactory();
        using var global = CreateClient(factory, TechnicalToken("loans.read loans.write"));
        var business = await CreateOriginApplication(global, Owner, "branch", Branch, "business-loan");
        using var employee = CreateClient(factory, Token(null, null,
            new Claim(ApiSecurity.TokenTypeClaim, "employee"), new Claim("role", role),
            new Claim(ApiSecurity.BranchIdClaim, Branch.ToString()), new Claim(ApiSecurity.AllowedProductClaim, "retail-loan")));
        var path = $"/loan-applications/{business.Id}";
        Assert.Equal(HttpStatusCode.Forbidden, (await employee.GetAsync(path)).StatusCode);
        var response = operation == "edit"
            ? await employee.PutAsJsonAsync(path, Request(Owner) with { Product = "retail-loan" })
            : await employee.PostAsync(path + "/submit", null);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Theory]
    [InlineData("scope", "operator")]
    [InlineData("scope", "unrelated operator loans.write")]
    [InlineData("roles", "operator")]
    public async Task External_role_claims_are_normalized_and_keep_operation_and_resource_restrictions(
        string claimType, string value)
    {
        using var factory = new ApiFactory();
        using var global = CreateClient(factory, TechnicalToken("loans.read loans.write"));
        var own = await CreateOriginApplication(global, Other, "branch", Branch);
        var digital = await CreateOriginApplication(global, Other, "digital");
        using var employee = CreateClient(factory, Token(null, null,
            new Claim(ApiSecurity.TokenTypeClaim, "employee"), new Claim(claimType, value),
            new Claim(ApiSecurity.BranchIdClaim, Branch.ToString())));
        Assert.Equal(HttpStatusCode.OK, (await employee.GetAsync($"/loan-applications/{own.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await employee.PutAsJsonAsync($"/loan-applications/{own.Id}",
            Request(Other) with { Product = "retail-loan", Amount = 2500 })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await employee.GetAsync($"/loan-applications/{digital.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await employee.PostAsJsonAsync("/loan-applications/", CreateRequest(Other))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await employee.PostAsync($"/loan-applications/{own.Id}/submit", null)).StatusCode);
    }

    [Theory]
    [InlineData("scope", "analyst")]
    [InlineData("scope", "operator.extra")]
    [InlineData("scope", "Operator")]
    [InlineData("scope", "loans.read loans.write")]
    [InlineData("app_role", "operator")]
    public async Task Unmapped_scopes_and_injected_internal_roles_grant_no_employee_access(string type, string value)
    {
        using var factory = new ApiFactory();
        using var employee = CreateClient(factory, Token(null, null,
            new Claim(ApiSecurity.TokenTypeClaim, "employee"), new Claim(type, value),
            new Claim(ApiSecurity.BranchIdClaim, Branch.ToString())));
        Assert.Equal(HttpStatusCode.Forbidden, (await employee.GetAsync("/loan-applications/")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await employee.PostAsJsonAsync("/loan-applications/", CreateRequest(Other))).StatusCode);
    }

    [Fact]
    public async Task Configured_scope_alias_uses_target_role_permissions()
    {
        using var factory = new ApiFactory(new Dictionary<string, string?>
        {
            ["Authorization:RoleMappings:11:Role"] = "operator"
        });
        using var global = CreateClient(factory, TechnicalToken("loans.read loans.write"));
        var own = await CreateOriginApplication(global, Other, "branch", Branch);
        using var analyst = CreateClient(factory, Token(null, null,
            new Claim(ApiSecurity.TokenTypeClaim, "employee"), new Claim("scope", "analyst"),
            new Claim(ApiSecurity.BranchIdClaim, Branch.ToString())));
        Assert.Equal(HttpStatusCode.NoContent, (await analyst.PutAsJsonAsync($"/loan-applications/{own.Id}",
            Request(Other) with { Product = "retail-loan" })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await analyst.PostAsync($"/loan-applications/{own.Id}/submit", null)).StatusCode);
    }

    [Fact]
    public async Task Client_and_technical_tokens_cannot_acquire_employee_roles_from_scopes()
    {
        using var factory = new ApiFactory();
        using var global = CreateClient(factory, TechnicalToken("loans.read loans.write"));
        var other = await CreateOriginApplication(global, Other, "branch", Branch);
        using var client = CreateClient(factory, Token(Owner.ToString(), null,
            new Claim("scope", "operator branch_advisor"), new Claim(ApiSecurity.BranchIdClaim, Branch.ToString())));
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync($"/loan-applications/{other.Id}")).StatusCode);
        using var technical = CreateClient(factory, TechnicalToken("operator branch_advisor"));
        Assert.Equal(HttpStatusCode.Forbidden, (await technical.GetAsync("/loan-applications/")).StatusCode);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Direct_handler_calls_enforce_authentication_and_operation_permissions(bool authenticated)
    {
        using var factory = new ApiFactory();
        using var scope = factory.Services.CreateScope();
        var user = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ApiSecurity.TokenTypeClaim, "technical"), new Claim("scope", "loans.read")],
            authenticated ? "test" : null));
        var cancellationToken = CancellationToken.None;

        AssertForbidden(
            await scope.ServiceProvider.GetRequiredService<CreateLoanApplication>().HandleAsync(user, new CreateLoanApplicationCommand(CreateRequest(Owner)), cancellationToken));
        var update = await scope.ServiceProvider.GetRequiredService<UpdateLoanApplication>()
            .HandleAsync(user, new UpdateLoanApplicationCommand(Guid.NewGuid(), Request(Owner)), cancellationToken);
        Assert.IsType<LoanNotFound>(update.Value);
        var submit = await scope.ServiceProvider.GetRequiredService<SubmitLoanApplication>()
            .HandleAsync(user, new SubmitLoanApplicationCommand(Guid.NewGuid()), cancellationToken);
        Assert.IsType<LoanNotFound>(submit.Value);
        var list = await scope.ServiceProvider.GetRequiredService<ListLoanApplications>().HandleAsync(user, new ListLoanApplicationsQuery(), cancellationToken);
        if (authenticated)
            Assert.Empty(Assert.IsType<LoanSuccess<LoanApplication[]>>(list.Value).Value);
        else
            AssertForbidden(list);
        Assert.Empty(await scope.ServiceProvider.GetRequiredService<LoansDbContext>()
            .LoanApplications.ToArrayAsync());
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Direct_submit_denies_existing_resource_without_permission(bool authenticated)
    {
        using var factory = new ApiFactory();
        using var global = CreateClient(factory, TechnicalToken("loans.read loans.write"));
        var application = await CreateOriginApplication(global, Owner, "branch", Branch);
        using var scope = factory.Services.CreateScope();
        var user = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ApiSecurity.TokenTypeClaim, "technical"), new Claim("scope", "loans.read")],
            authenticated ? "test" : null));

        var result = await scope.ServiceProvider.GetRequiredService<SubmitLoanApplication>()
            .HandleAsync(user, new SubmitLoanApplicationCommand(application.Id), CancellationToken.None);

        Assert.IsType<LoanForbidden>(result.Value);
        var persisted = await scope.ServiceProvider.GetRequiredService<LoansDbContext>()
            .LoanApplications.AsNoTracking().SingleAsync(item => item.Id == application.Id);
        Assert.Equal(LoanApplicationStatus.Draft, persisted.Status);
        Assert.Null(persisted.SubmittedAt);
    }

    [Theory]
    [InlineData("owner")]
    [InlineData("product")]
    [InlineData("channel")]
    public async Task Direct_create_rejects_valid_requests_outside_resource_scope(string restriction)
    {
        using var factory = new ApiFactory();
        using var scope = factory.Services.CreateScope();
        var claims = restriction == "owner"
            ? new[] { new Claim(ApiSecurity.TokenTypeClaim, "client"), new Claim(ApiSecurity.ClientIdClaim, Owner.ToString()) }
            : new[]
            {
                new Claim(ApiSecurity.TokenTypeClaim, "technical"), new Claim("scope", "loans.write"),
                new Claim(ApiSecurity.AllowedProductClaim, "retail-loan"), new Claim(ApiSecurity.AllowedChannelClaim, "store")
            };
        var user = new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
        var request = Request(restriction == "owner" ? Other : Owner) with
        {
            Product = restriction == "product" ? "business-loan" : "retail-loan",
            Channel = restriction == "channel" ? "digital" : "store"
        };
        var operation = scope.ServiceProvider
            .GetRequiredService<CreateLoanApplication>();
        AssertForbidden(
            await operation.HandleAsync(user, new CreateLoanApplicationCommand(request), CancellationToken.None));
        Assert.Empty(await scope.ServiceProvider.GetRequiredService<LoansDbContext>().LoanApplications.ToArrayAsync());
    }

    [Fact]
    public void Empty_union_result_cannot_be_mapped_to_a_success_response()
    {
        Assert.Throws<InvalidOperationException>(() =>
            default(LoanApplicationResult<LoanApplication>).ToHttpResult());
    }

    private static void AssertForbidden<T>(LoanApplicationResult<T> result) => Assert.True(result is LoanForbidden);

    private static string EmployeeToken(string branchId, string role = "seller") => Token(null, null,
        new Claim(ApiSecurity.TokenTypeClaim, "employee"), new Claim("role", role),
        new Claim(ApiSecurity.BranchIdClaim, branchId));

    private static string StoreToken(string scope) => Token(null, null,
        new Claim(ApiSecurity.TokenTypeClaim, "technical"), new Claim("scope", scope),
        new Claim(ApiSecurity.AllowedProductClaim, "retail-loan"), new Claim(ApiSecurity.AllowedChannelClaim, "store"));

    private static async Task<LoanApplication> CreateOriginApplication(
        HttpClient client, Guid clientId, string channel, Guid? branchId = null, string product = "retail-loan")
    {
        var response = await client.PostAsJsonAsync("/loan-applications/", CreateRequest(clientId) with
        { Product = product, Channel = channel, BranchId = branchId });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<LoanApplication>(JsonOptions))!;
    }

    private static string ProductToken(string scope, string product) => Token(null, null,
        new Claim(ApiSecurity.TokenTypeClaim, "technical"), new Claim("scope", scope),
        new Claim(ApiSecurity.AllowedProductClaim, product));

    private static async Task<LoanApplication> CreateApplication(HttpClient client, Guid clientId, string? product)
    {
        var created = await client.PostAsJsonAsync("/loan-applications/", CreateRequest(clientId) with { Product = product });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        return (await created.Content.ReadFromJsonAsync<LoanApplication>(JsonOptions))!;
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

    private sealed class TestEmployeeBranchResolver(string employeeId, Guid branchId) : IEmployeeBranchResolver
    {
        public int Calls { get; private set; }

        public Task<Guid?> ResolveAsync(string id, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult<Guid?>(id == employeeId ? branchId : null);
        }
    }

    private sealed class ApiFactory(Dictionary<string, string?>? overrides = null,
        IEmployeeBranchResolver? branchResolver = null) : WebApplicationFactory<Program>
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
            if (overrides is not null)
                builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(overrides));
            builder.ConfigureServices(services =>
            {
                if (branchResolver is not null)
                    services.AddSingleton(branchResolver);
                services.RemoveAll<DbContextOptions<LoansDbContext>>();
                services.RemoveAll<IDbContextOptionsConfiguration<LoansDbContext>>();
                services.AddDbContext<LoansDbContext>(options => options.UseInMemoryDatabase(database));
            });
        }
    }
}

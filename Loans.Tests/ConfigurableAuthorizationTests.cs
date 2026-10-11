using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using Loans;
using ConfigurableAuthorization;
using Loans.Features.LoanApplications.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Loans.Tests;

public sealed partial class ApiSecurityTests
{
    [Fact]
    public async Task New_role_and_mapping_can_be_added_entirely_in_configuration()
    {
        using var factory = new ApiFactory(new()
        {
            ["Authorization:RoleMappings:14:Actor"] = "employee",
            ["Authorization:RoleMappings:14:ClaimType"] = "scope",
            ["Authorization:RoleMappings:14:Value"] = "review",
            ["Authorization:RoleMappings:14:Role"] = "reviewer",
            ["Authorization:Roles:reviewer:Services:loans:Grants:0:Permissions:0"] = "loans.read",
            ["Authorization:Roles:reviewer:Services:loans:Grants:0:Scope"] = "All"
        });
        using var global = CreateClient(factory, TechnicalToken("loans.write"));
        var digital = await CreateOriginApplication(global, Other, "digital");
        // The All grant does not require branch_id.
        using var reviewer = CreateClient(factory, Token(null, null,
            new Claim(ApiSecurity.TokenTypeClaim, "employee"), new Claim("scope", "review")));
        Assert.Equal(HttpStatusCode.OK, (await reviewer.GetAsync($"/loan-applications/{digital.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await reviewer.PutAsJsonAsync($"/loan-applications/{digital.Id}", Request(Other))).StatusCode);
        using var technical = CreateClient(factory, TechnicalToken("review"));
        Assert.Equal(HttpStatusCode.Forbidden, (await technical.GetAsync("/loan-applications/")).StatusCode);
    }

    [Fact]
    public async Task Global_read_and_branch_edit_grants_do_not_combine_into_global_edit()
    {
        using var factory = new ApiFactory(new()
        {
            ["Authorization:Roles:analyst:Services:loans:Grants:0:Permissions:0"] = "loans.read",
            ["Authorization:Roles:analyst:Services:loans:Grants:0:Scope"] = "All"
        });
        using var global = CreateClient(factory, TechnicalToken("loans.write"));
        var own = await CreateOriginApplication(global, Other, "branch", Branch);
        var other = await CreateOriginApplication(global, Other, "branch", OtherBranch);
        var digital = await CreateOriginApplication(global, Other, "digital");
        using var employee = CreateClient(factory, Token(null, null,
            new Claim(ApiSecurity.TokenTypeClaim, "employee"), new Claim("role", "operator"),
            new Claim("scope", "analyst"), new Claim(ApiSecurity.BranchIdClaim, Branch.ToString())));
        foreach (var application in new[] { own, other, digital })
            Assert.Equal(HttpStatusCode.OK, (await employee.GetAsync($"/loan-applications/{application.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await employee.PutAsJsonAsync($"/loan-applications/{own.Id}",
            Request(Other) with { Product = "retail-loan" })).StatusCode);
        foreach (var application in new[] { other, digital })
            Assert.Equal(HttpStatusCode.Forbidden, (await employee.PutAsJsonAsync($"/loan-applications/{application.Id}",
                Request(Other) with { Product = "retail-loan" })).StatusCode);
    }

    private static Dictionary<string, string?> CorrelatedGrants() => new()
    {
        ["Authorization:Roles:analyst:Services:loans:Grants:0:Permissions:0"] = "loans.read",
        ["Authorization:Roles:analyst:Services:loans:Grants:0:Scope"] = "All",
        ["Authorization:Roles:analyst:Services:loans:Grants:0:Products:0"] = "retail-loan",
        ["Authorization:Roles:analyst:Services:loans:Grants:0:Channels:0"] = "store",
        ["Authorization:Roles:analyst:Services:loans:Grants:1:Permissions:0"] = "loans.read",
        ["Authorization:Roles:analyst:Services:loans:Grants:1:Scope"] = "OwnBranch",
        ["Authorization:Roles:analyst:Services:loans:Grants:1:Products:0"] = "business-loan"
    };

    [Fact]
    public async Task Product_channel_and_branch_stay_correlated_within_each_grant_and_token_filters_intersect()
    {
        using var factory = new ApiFactory(CorrelatedGrants());
        using var global = CreateClient(factory, TechnicalToken("loans.write"));
        var retailStore = await CreateOriginApplication(global, Other, "store");
        var businessBranch = await CreateOriginApplication(global, Other, "branch", Branch, "business-loan");
        var rejected = new[]
        {
            await CreateOriginApplication(global, Other, "branch", Branch),
            await CreateOriginApplication(global, Other, "store", null, "business-loan"),
            await CreateOriginApplication(global, Other, "branch", OtherBranch, "business-loan")
        };
        var claims = new[] { new Claim(ApiSecurity.TokenTypeClaim, "employee"), new Claim("scope", "analyst"),
            new Claim(ApiSecurity.BranchIdClaim, Branch.ToString()) };
        using var employee = CreateClient(factory, Token(null, null, claims));
        var list = (await employee.GetFromJsonAsync<LoanApplication[]>("/loan-applications/", JsonOptions))!;
        Assert.Equal(new[] { retailStore.Id, businessBranch.Id }.Order(), list.Select(a => a.Id).Order());
        foreach (var application in rejected)
            Assert.Equal(HttpStatusCode.Forbidden, (await employee.GetAsync($"/loan-applications/{application.Id}")).StatusCode);
        var page = (await employee.GetFromJsonAsync<LoanApplication[]>("/loan-applications/?skip=1&take=1", JsonOptions))!;
        Assert.Equal(list[1].Id, Assert.Single(page).Id);

        using var narrowed = CreateClient(factory, Token(null, null,
            claims.Append(new Claim(ApiSecurity.AllowedProductClaim, "retail-loan")).ToArray()));
        Assert.Equal(retailStore.Id, Assert.Single((await narrowed.GetFromJsonAsync<LoanApplication[]>("/loan-applications/", JsonOptions))!).Id);
        Assert.Equal(HttpStatusCode.Forbidden, (await narrowed.GetAsync($"/loan-applications/{businessBranch.Id}")).StatusCode);
    }

    [Fact]
    public async Task A_technical_service_can_receive_a_configured_product_and_channel_grant()
    {
        using var factory = new ApiFactory(new()
        {
            ["Authorization:RoleMappings:14:Actor"] = "technical",
            ["Authorization:RoleMappings:14:ClaimType"] = "service_id",
            ["Authorization:RoleMappings:14:Value"] = "retail-store",
            ["Authorization:RoleMappings:14:Role"] = "store_reader",
            ["Authorization:Roles:store_reader:Services:loans:Grants:0:Permissions:0"] = "loans.read",
            ["Authorization:Roles:store_reader:Services:loans:Grants:0:Scope"] = "All",
            ["Authorization:Roles:store_reader:Services:loans:Grants:0:Products:0"] = "retail-loan",
            ["Authorization:Roles:store_reader:Services:loans:Grants:0:Channels:0"] = "store"
        });
        using var global = CreateClient(factory, TechnicalToken("loans.write"));
        var store = await CreateOriginApplication(global, Other, "store");
        var digital = await CreateOriginApplication(global, Other, "digital");
        using var service = CreateClient(factory, Token(null, null,
            new Claim(ApiSecurity.TokenTypeClaim, "technical"), new Claim("service_id", "retail-store")));
        Assert.Equal(store.Id, Assert.Single((await service.GetFromJsonAsync<LoanApplication[]>("/loan-applications/", JsonOptions))!).Id);
        Assert.Equal(HttpStatusCode.Forbidden, (await service.GetAsync($"/loan-applications/{digital.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await service.PostAsync($"/loan-applications/{store.Id}/submit", null)).StatusCode);
    }

    [Fact]
    public async Task Transformation_is_idempotent_does_not_mutate_input_and_discards_forged_internal_claims()
    {
        using var factory = new ApiFactory();
        var transformation = factory.Services.GetRequiredService<IClaimsTransformation>();
        var original = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim(ApiSecurity.TokenTypeClaim, "employee"), new Claim("scope", "analyst"),
            new Claim("app_role", "operator"), new Claim("app_permission", "loans.edit")
        }, "test"));
        var first = await transformation.TransformAsync(original);
        var second = await transformation.TransformAsync(first);
        Assert.Equal("analyst", Assert.Single(second.FindAll("app_role")).Value);
        Assert.True(second.IsInRole("analyst"));
        Assert.False(second.IsInRole("operator"));
        Assert.Empty(second.FindAll("app_permission"));
        Assert.Equal(first.Identities.Count(), second.Identities.Count());
        Assert.True(original.HasClaim("app_role", "operator"));
        var anonymous = await transformation.TransformAsync(new ClaimsPrincipal(new ClaimsIdentity(original.Claims)));
        Assert.Empty(anonymous.FindAll("app_role"));
        Assert.DoesNotContain(anonymous.Identities, i => i.IsAuthenticated);
    }

    [Theory]
    [InlineData("Authorization:Roles:operator:Services:loans:Grants:0:Scope", "Unknown")]
    [InlineData("Authorization:Roles:operator:Services:loans:Grants:0:Permissions:0", "loans.unknown")]
    [InlineData("Authorization:RoleMappings:0:Role", "unknown-role")]
    [InlineData("Authorization:RoleMappings:0:Actor", "unknown-actor")]
    [InlineData("Authorization:Roles:operator:Services:loans:Grants:0:Channels:0", "unknown-channel")]
    public void Invalid_authorization_configuration_prevents_startup(string key, string value)
    {
        using var factory = new ApiFactory(new() { [key] = value });
        Assert.Throws<OptionsValidationException>(() => factory.CreateClient());
    }

    [Fact]
    public void Removed_default_channel_setting_is_rejected_at_startup()
    {
        using var factory = new ApiFactory(new()
        {
            ["Authorization:Roles:operator:Services:loans:Grants:0:DefaultChannel"] = "digital"
        });
        Assert.Throws<InvalidOperationException>(() => factory.CreateClient());
    }

    [Fact]
    public async Task Missing_channel_is_rejected_and_an_explicit_branch_requires_an_explicit_branch_id()
    {
        using var factory = new ApiFactory();
        using var client = CreateClient(factory, TechnicalToken("loans.write"));
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/loan-applications/",
            Request(Other) with { Channel = null })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/loan-applications/",
            Request(Other) with { Channel = "branch" })).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await client.PostAsJsonAsync("/loan-applications/",
            Request(Other) with { Channel = "branch", BranchId = Branch })).StatusCode);
    }

    [Fact]
    public async Task Only_the_dedicated_resource_is_authorized_and_it_is_an_immutable_snapshot()
    {
        using var factory = new ApiFactory();
        using var scope = factory.Services.CreateScope();
        var authorization = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        var user = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ApiSecurity.ClientIdClaim, Owner.ToString())], "test"));
        var entity = new LoanApplicationEntity { ClientId = Owner, Product = "retail-loan", Channel = "digital" };
        var resource = LoanApplicationResource.From(entity);
        var requirement = new[] { new PermissionRequirement(LoanPermissions.Read) };
        Assert.True((await authorization.AuthorizeAsync(user, resource, requirement)).Succeeded);
        Assert.False((await authorization.AuthorizeAsync(user, entity, requirement)).Succeeded);
        Assert.False((await authorization.AuthorizeAsync(user, Request(Owner), requirement)).Succeeded);
        Assert.False((await authorization.AuthorizeAsync(user, null, requirement)).Succeeded);

        entity.ClientId = Other;
        Assert.Equal(Owner, resource.ClientId);
        Assert.True((await authorization.AuthorizeAsync(user, resource, requirement)).Succeeded);
        Assert.False((await authorization.AuthorizeAsync(user, LoanApplicationResource.From(entity), requirement)).Succeeded);
    }

    [Theory]
    [InlineData("owner")]
    [InlineData("product")]
    [InlineData("channel")]
    [InlineData("branch")]
    public async Task Direct_update_checks_stored_resource_even_when_payload_matches_the_callers_scope(string restriction)
    {
        using var factory = new ApiFactory();
        using var global = CreateClient(factory, TechnicalToken("loans.read loans.write"));
        var application = await CreateOriginApplication(global, Other,
            restriction == "channel" ? "digital" : "branch", restriction == "channel" ? null : OtherBranch,
            restriction == "product" ? "business-loan" : "retail-loan");
        Claim[] claims = restriction switch
        {
            "owner" => [new(ApiSecurity.ClientIdClaim, Owner.ToString())],
            "branch" => [new(ApiSecurity.TokenTypeClaim, "employee"), new("role", "operator"),
                new(ApiSecurity.BranchIdClaim, Branch.ToString())],
            _ => [new(ApiSecurity.TokenTypeClaim, "technical"), new("scope", "loans.read loans.write"),
                new(restriction == "product" ? ApiSecurity.AllowedProductClaim : ApiSecurity.AllowedChannelClaim,
                    restriction == "product" ? "retail-loan" : "store")]
        };
        var user = new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
        using var scope = factory.Services.CreateScope();
        var payload = Request(restriction == "owner" ? Owner : Other) with
        {
            Product = "retail-loan", Amount = 9000,
            Channel = restriction == "channel" ? "store" : "branch",
            BranchId = restriction == "channel" ? null : Branch
        };
        var update = await scope.ServiceProvider.GetRequiredService<Loans.Features.LoanApplications.UpdateLoanApplication>()
            .HandleAsync(user, new(application.Id, payload), CancellationToken.None);
        Assert.IsType<Loans.Features.LoanApplications.LoanForbidden>(update.Value);
        var persisted = await scope.ServiceProvider.GetRequiredService<LoansDbContext>()
            .LoanApplications.AsNoTracking().SingleAsync(loan => loan.Id == application.Id);
        Assert.Equal(application.ClientId, persisted.ClientId);
        Assert.Equal(application.Product, persisted.Product);
        Assert.Equal(application.Channel, persisted.Channel);
        Assert.Equal(application.BranchId, persisted.BranchId);
        Assert.Equal(application.Amount, persisted.Amount);
    }
}

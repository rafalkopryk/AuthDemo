using System.Net;
using System.Net.Http.Json;
using Loans;
using Xunit;

namespace Loans.Tests;

public sealed partial class ApiSecurityTests
{
    [Fact]
    public async Task Access_limits_list_and_preserves_client_filter_rejection()
    {
        using var factory = new ApiFactory();
        using var owner = CreateClient(factory, Token(Owner.ToString()));
        using var other = CreateClient(factory, Token(Other.ToString()));
        using var reader = CreateClient(factory, TechnicalToken("loans.read"));
        for (var i = 0; i < 3; i++)
        {
            Assert.Equal(HttpStatusCode.Created, (await owner.PostAsJsonAsync("/loan-applications/", CreateRequest(Owner))).StatusCode);
            Assert.Equal(HttpStatusCode.Created, (await other.PostAsJsonAsync("/loan-applications/", CreateRequest(Other))).StatusCode);
        }
        var own = (await owner.GetFromJsonAsync<LoanApplication[]>("/loan-applications/?skip=1&take=2", JsonOptions))!;
        Assert.Equal(2, own.Length);
        Assert.All(own, loan => Assert.Equal(Owner, loan.ClientId));
        foreach (var loan in own)
            Assert.Equal(HttpStatusCode.OK, (await owner.GetAsync($"/loan-applications/{loan.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await owner.GetAsync($"/loan-applications/?clientId={Other}")).StatusCode);
        Assert.Equal(6, (await reader.GetFromJsonAsync<LoanApplication[]>("/loan-applications/", JsonOptions))!.Length);
        var filtered = (await reader.GetFromJsonAsync<LoanApplication[]>($"/loan-applications/?clientId={Other}", JsonOptions))!;
        Assert.Equal(3, filtered.Length);
        Assert.All(filtered, loan => Assert.Equal(Other, loan.ClientId));
    }
}

using LightAuthorization;
using Loans.Features.LoanApplications.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;

namespace Loans;

public static class ApiSecurity
{
    public const string ReadPolicy = "LoansRead";
    public const string CreatePolicy = "LoansCreate";
    public const string EditPolicy = "LoansEdit";
    public const string SubmitPolicy = "LoansSubmit";
    public const string ReadScope = "loans.read";
    public const string WriteScope = "loans.write";
    public const string TokenTypeClaim = "token_type";
    public const string ClientIdClaim = "client_id";

    public static void AddApiSecurity(this WebApplicationBuilder builder)
    {
        var settings = builder.Configuration.GetSection("Authentication:Schemes:Bearer");
        if (!builder.Environment.IsDevelopment())
        {
            if (!Uri.TryCreate(settings["Authority"], UriKind.Absolute, out var authority)
                || authority.Scheme != Uri.UriSchemeHttps
                || string.IsNullOrWhiteSpace(settings["Audience"]))
                throw new InvalidOperationException(
                    "Configure an HTTPS Authentication:Schemes:Bearer:Authority and Audience outside Development.");
        }

        builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                // The framework loads local user-jwts signing keys from user secrets.
                options.Authority = settings["Authority"];
                options.Audience = settings["Audience"];
                options.MapInboundClaims = false;
                options.RequireHttpsMetadata = true;
                options.IncludeErrorDetails = builder.Environment.IsDevelopment();
                options.TokenValidationParameters.ValidateIssuer = true;
                options.TokenValidationParameters.ValidateAudience = true;
                options.TokenValidationParameters.ValidateLifetime = true;
                options.TokenValidationParameters.ValidateIssuerSigningKey = true;
                options.TokenValidationParameters.RequireSignedTokens = true;
                options.TokenValidationParameters.RequireExpirationTime = true;
                options.TokenValidationParameters.ClockSkew = TimeSpan.FromSeconds(30);
            });

        builder.Services.AddLoanAuthorization(builder.Configuration);
        var authorization = builder.Services.AddAuthorizationBuilder()
            .SetFallbackPolicy(new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser().Build());
        foreach (var (name, permission) in new[]
                 {
                     (ReadPolicy, LoanPermissions.Read), (CreatePolicy, LoanPermissions.Create),
                     (EditPolicy, LoanPermissions.Edit), (SubmitPolicy, LoanPermissions.Submit)
                 })
        {
            authorization.AddPolicy(name, policy => policy
                .RequireAuthenticatedUser()
                .AddRequirements(new PermissionPresenceRequirement(permission)));
        }
    }
}

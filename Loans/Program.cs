using System.Text.Json.Serialization;
using Loans;
using Loans.Features.LoanApplications;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

builder.AddApiSecurity();
builder.Services.AddOpenApi(options => options.AddDocumentTransformer((document, context, cancellationToken) =>
{
    document.Components ??= new OpenApiComponents();
    document.Components.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>();
    document.Components.SecuritySchemes["Bearer"] = new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        Description = "Paste a client JWT, technical JWT with loans.read / loans.write and optional product/channel restrictions, or employee JWT with seller, operator or branch_advisor role and branch_id (or employee_id with a branch resolver)."
    };
    document.Security = [new OpenApiSecurityRequirement
    {
        [new OpenApiSecuritySchemeReference("Bearer", document)] = []
    }];
    return Task.CompletedTask;
}));
builder.Services.ConfigureHttpJsonOptions(options =>
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));
builder.Services.AddDbContext<LoansDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("loansdb")
        ?? throw new InvalidOperationException("The 'loansdb' connection string is not configured.")));
builder.Services.AddLoanApplicationOperations();

var app = builder.Build();

app.MapDefaultEndpoints();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi().AllowAnonymous();
    app.UseSwaggerUI(options =>
        options.SwaggerEndpoint("/openapi/v1.json", "Loans API v1"));
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapLoanApplicationEndpoints();

app.Run();

public partial class Program;

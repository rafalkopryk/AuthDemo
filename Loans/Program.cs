using System.Text.Json.Serialization;
using Loans;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

builder.Services.AddOpenApi();
builder.Services.ConfigureHttpJsonOptions(options =>
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));
builder.Services.AddDbContext<LoansDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("loansdb")
        ?? throw new InvalidOperationException("The 'loansdb' connection string is not configured.")));
builder.Services.AddScoped<LoanApplicationStore>();

var app = builder.Build();

app.MapDefaultEndpoints();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.UseSwaggerUI(options =>
        options.SwaggerEndpoint("/openapi/v1.json", "Loans API v1"));
}

app.UseHttpsRedirection();

app.MapLoanApplicationEndpoints();

app.Run();

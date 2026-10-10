var builder = DistributedApplication.CreateBuilder(args);

var postgres = builder.AddPostgres("postgres").WithDataVolume();
var loansDatabase = postgres.AddDatabase("loansdb");

var loans = builder.AddDotnetProject("loans", "../Loans/Loans.csproj")
    .WithReference(loansDatabase)
    .WaitFor(loansDatabase);

var migrations = loans.AddEFMigrations("loans-migrations", "Loans.LoansDbContext",
        configureToolResource: tool => tool
            .WithToolVersion("11.0.0-rc.1.26425.128")
            .WithToolPrerelease())
    .RunDatabaseUpdateOnStart();

loans.WaitForCompletion(migrations);

builder.Build().Run();

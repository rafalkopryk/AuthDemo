using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Loans;

public sealed class LoansDbContext(DbContextOptions<LoansDbContext> options) : DbContext(options)
{
    public DbSet<LoanApplicationEntity> LoanApplications => Set<LoanApplicationEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        var application = modelBuilder.Entity<LoanApplicationEntity>();
        application.ToTable("LoanApplications");
        application.HasKey(item => item.Id);
        application.Property(item => item.ApplicantName).HasMaxLength(200).IsRequired();
        application.Property(item => item.Amount).HasPrecision(18, 2);
        application.Property(item => item.Purpose).HasMaxLength(2000);
        application.Property(item => item.Status).HasConversion<int>();
    }
}

public sealed class LoansDbContextFactory : IDesignTimeDbContextFactory<LoansDbContext>
{
    public LoansDbContext CreateDbContext(string[] args)
    {
        var connectionString = Environment.GetEnvironmentVariable("ConnectionStrings__loansdb")
            ?? "Host=localhost;Database=loansdb;Username=postgres;Password=postgres";

        var options = new DbContextOptionsBuilder<LoansDbContext>()
            .UseNpgsql(connectionString)
            .Options;

        return new LoansDbContext(options);
    }
}

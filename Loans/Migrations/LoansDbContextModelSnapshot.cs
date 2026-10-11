using System;
using Loans;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

#nullable disable

namespace Loans.Migrations;

[DbContext(typeof(LoansDbContext))]
partial class LoansDbContextModelSnapshot : ModelSnapshot
{
    protected override void BuildModel(ModelBuilder modelBuilder)
    {
#pragma warning disable 612, 618
        modelBuilder
            .HasAnnotation("ProductVersion", "11.0.0-rc.1.26425.128")
            .HasAnnotation("Relational:MaxIdentifierLength", 63);

        modelBuilder.Entity<LoanApplicationEntity>(entity =>
        {
            entity.Property<Guid>("Id")
                .HasColumnType("uuid");

            entity.Property<decimal>("Amount")
                .HasPrecision(18, 2)
                .HasColumnType("numeric(18,2)");

            entity.Property<string>("ApplicantName")
                .IsRequired()
                .HasMaxLength(200)
                .HasColumnType("character varying(200)");

            entity.Property<Guid?>("BranchId")
                .HasColumnType("uuid");

            entity.Property<string>("Channel")
                .HasMaxLength(16)
                .HasColumnType("character varying(16)");

            entity.Property<Guid>("ClientId")
                .HasColumnType("uuid");

            entity.Property<DateTimeOffset>("CreatedAt")
                .HasColumnType("timestamp with time zone");

            entity.Property<string>("Product")
                .HasMaxLength(64)
                .HasColumnType("character varying(64)");

            entity.Property<string>("Purpose")
                .HasMaxLength(2000)
                .HasColumnType("character varying(2000)");

            entity.Property<LoanApplicationStatus>("Status")
                .HasConversion<int>()
                .HasColumnType("integer");

            entity.Property<DateTimeOffset?>("SubmittedAt")
                .HasColumnType("timestamp with time zone");

            entity.Property<int>("TermMonths")
                .HasColumnType("integer");

            entity.HasKey("Id");
            entity.ToTable("LoanApplications");
        });
#pragma warning restore 612, 618
    }
}

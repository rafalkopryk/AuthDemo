using System;
using Loans;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Loans.Migrations;

[DbContext(typeof(LoansDbContext))]
[Migration("20261010190000_InitialCreate")]
public partial class InitialCreate : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "LoanApplications",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "uuid", nullable: false),
                ClientId = table.Column<Guid>(type: "uuid", nullable: false),
                ApplicantName = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                Amount = table.Column<decimal>(type: "numeric(18,2)", precision: 18, scale: 2, nullable: false),
                TermMonths = table.Column<int>(type: "integer", nullable: false),
                Purpose = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                Status = table.Column<int>(type: "integer", nullable: false),
                CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                SubmittedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
            },
            constraints: table => table.PrimaryKey("PK_LoanApplications", row => row.Id));
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "LoanApplications");
    }
}

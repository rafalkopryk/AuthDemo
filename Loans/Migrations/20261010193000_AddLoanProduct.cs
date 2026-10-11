using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Loans.Migrations;

[DbContext(typeof(LoansDbContext))]
[Migration("20261010193000_AddLoanProduct")]
public sealed class AddLoanProduct : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder) =>
        migrationBuilder.AddColumn<string>(
            name: "Product", table: "LoanApplications", type: "character varying(64)",
            maxLength: 64, nullable: true);

    protected override void Down(MigrationBuilder migrationBuilder) =>
        migrationBuilder.DropColumn(name: "Product", table: "LoanApplications");
}

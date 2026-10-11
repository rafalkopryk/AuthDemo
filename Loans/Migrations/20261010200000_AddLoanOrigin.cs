using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Loans.Migrations;

[DbContext(typeof(LoansDbContext))]
[Migration("20261010200000_AddLoanOrigin")]
public sealed class AddLoanOrigin : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<string>(name: "Channel", table: "LoanApplications",
            type: "character varying(16)", maxLength: 16, nullable: true);
        migrationBuilder.AddColumn<Guid>(name: "BranchId", table: "LoanApplications",
            type: "uuid", nullable: true);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropColumn(name: "Channel", table: "LoanApplications");
        migrationBuilder.DropColumn(name: "BranchId", table: "LoanApplications");
    }
}

using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace UserAuthentication.Migrations
{
    /// <inheritdoc />
    public partial class UpdateUserTbl01 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "EmailCOnfirmationToken",
                table: "AspNetUsers",
                newName: "EmailConfirmationToken");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "EmailConfirmationToken",
                table: "AspNetUsers",
                newName: "EmailCOnfirmationToken");
        }
    }
}

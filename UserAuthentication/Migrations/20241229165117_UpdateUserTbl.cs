using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace UserAuthentication.Migrations
{
    /// <inheritdoc />
    public partial class UpdateUserTbl : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "EmailCOnfirmationToken",
                table: "AspNetUsers",
                type: "nvarchar(max)",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "EmailCOnfirmationToken",
                table: "AspNetUsers");
        }
    }
}

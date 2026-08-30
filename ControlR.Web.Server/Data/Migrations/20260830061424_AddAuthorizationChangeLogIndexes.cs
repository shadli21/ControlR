using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ControlR.Web.Server.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddAuthorizationChangeLogIndexes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateIndex(
                name: "IX_AuthorizationChangeLogs_ActorPrincipalId",
                table: "AuthorizationChangeLogs",
                column: "ActorPrincipalId");

            migrationBuilder.CreateIndex(
                name: "IX_AuthorizationChangeLogs_TargetId",
                table: "AuthorizationChangeLogs",
                column: "TargetId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_AuthorizationChangeLogs_ActorPrincipalId",
                table: "AuthorizationChangeLogs");

            migrationBuilder.DropIndex(
                name: "IX_AuthorizationChangeLogs_TargetId",
                table: "AuthorizationChangeLogs");
        }
    }
}

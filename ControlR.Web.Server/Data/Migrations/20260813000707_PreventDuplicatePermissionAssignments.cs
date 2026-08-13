using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ControlR.Web.Server.Data.Migrations;

/// <inheritdoc />
public partial class PreventDuplicatePermissionAssignments : Migration
{
  /// <inheritdoc />
  protected override void Up(MigrationBuilder migrationBuilder)
  {
    migrationBuilder.CreateIndex(
        name: "IX_PermissionAssignments_PrincipalKind_PrincipalId_PermissionN~",
        table: "PermissionAssignments",
        columns: new[] { "PrincipalKind", "PrincipalId", "PermissionName", "ScopeKind", "ScopeId", "Effect" },
        unique: true)
        .Annotation("Npgsql:NullsDistinct", false);
  }

  /// <inheritdoc />
  protected override void Down(MigrationBuilder migrationBuilder)
  {
    migrationBuilder.DropIndex(
        name: "IX_PermissionAssignments_PrincipalKind_PrincipalId_PermissionN~",
        table: "PermissionAssignments");
  }
}

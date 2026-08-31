using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ControlR.Web.Server.Data.Migrations;

/// <inheritdoc />
public partial class AddPrincipalAccessModes : Migration
{
  /// <inheritdoc />
  protected override void Up(MigrationBuilder migrationBuilder)
  {
    migrationBuilder.AddColumn<string>(
        name: "AccessMode",
        table: "ServiceAccounts",
        type: "character varying(50)",
        maxLength: 50,
        nullable: false,
        defaultValue: "Restricted");

    migrationBuilder.AddColumn<string>(
        name: "PermissionMode",
        table: "PersonalAccessTokens",
        type: "character varying(50)",
        maxLength: 50,
        nullable: false,
        defaultValue: "Restricted");

    // Backfill: preserve each existing principal's prior (inferred) behavior.
    //
    // PATs previously fell back to owner rules only when they had no ENABLED scope rows
    // (the loader's patRules query filtered IsEnabled), so PATs without enabled rows
    // behave as InheritOwner. PATs with at least one enabled row stay Restricted (the column default).
    // PrincipalKind and Kind are string-converted columns.
    migrationBuilder.Sql("""
              UPDATE "PersonalAccessTokens" pat
              SET "PermissionMode" = 'InheritOwner'
              WHERE NOT EXISTS (
                SELECT 1 FROM "PermissionAssignments" pa
                WHERE pa."PrincipalKind" = 'PersonalAccessToken'
                  AND pa."PrincipalId" = pat."Id"
                  AND pa."IsEnabled");
              """);

    // Server service accounts previously bypassed only when they had NO assignment rows
    // at all (the loader's absence check ignored IsEnabled), so row-free server accounts
    // behave as Unrestricted. Accounts with any row stay Restricted (the column default).
    // Tenant service accounts are never governed by the mode and stay at the default.
    migrationBuilder.Sql("""
              UPDATE "ServiceAccounts" sa
              SET "AccessMode" = 'Unrestricted'
              WHERE sa."Kind" = 'Server'
                AND NOT EXISTS (
                  SELECT 1 FROM "PermissionAssignments" pa
                  WHERE pa."PrincipalKind" = 'ServiceAccount'
                    AND pa."PrincipalId" = sa."Id");
              """);
  }

  /// <inheritdoc />
  protected override void Down(MigrationBuilder migrationBuilder)
  {
    migrationBuilder.DropColumn(
        name: "AccessMode",
        table: "ServiceAccounts");

    migrationBuilder.DropColumn(
        name: "PermissionMode",
        table: "PersonalAccessTokens");
  }
}

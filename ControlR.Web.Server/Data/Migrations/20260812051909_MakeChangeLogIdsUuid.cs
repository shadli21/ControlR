using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ControlR.Web.Server.Data.Migrations;

/// <inheritdoc />
public partial class MakeChangeLogIdsUuid : Migration
{
  /// <inheritdoc />
  protected override void Up(MigrationBuilder migrationBuilder)
  {
    // Normalize legacy values before the varchar -> uuid cast:
    //  - Empty GUID placeholders (written by pre-save ID reads) become NULL.
    //  - Any value that is not a valid UUID string is also NULLed so the
    //    column cast cannot fail on malformed data.
    migrationBuilder.Sql("""
              UPDATE "AuthorizationChangeLogs"
              SET "ActorPrincipalId" = NULL
              WHERE "ActorPrincipalId" IS NOT NULL
                AND (
                  "ActorPrincipalId" = '00000000-0000-0000-0000-000000000000'
                  OR NOT "ActorPrincipalId" ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
                );
              """);

    migrationBuilder.Sql("""
              UPDATE "AuthorizationChangeLogs"
              SET "TargetId" = NULL
              WHERE "TargetId" IS NOT NULL
                AND (
                  "TargetId" = '00000000-0000-0000-0000-000000000000'
                  OR NOT "TargetId" ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
                );
              """);

    // Cast via an explicit USING clause; PostgreSQL will not auto-cast
    // varchar to uuid when the column has values.
    migrationBuilder.Sql("""
              ALTER TABLE "AuthorizationChangeLogs"
              ALTER COLUMN "ActorPrincipalId" TYPE uuid
              USING "ActorPrincipalId"::uuid;
              """);

    migrationBuilder.Sql("""
              ALTER TABLE "AuthorizationChangeLogs"
              ALTER COLUMN "TargetId" TYPE uuid
              USING "TargetId"::uuid;
              """);
  }

  /// <inheritdoc />
  protected override void Down(MigrationBuilder migrationBuilder)
  {
    migrationBuilder.AlterColumn<string>(
        name: "TargetId",
        table: "AuthorizationChangeLogs",
        type: "character varying(100)",
        maxLength: 100,
        nullable: true,
        oldClrType: typeof(Guid),
        oldType: "uuid",
        oldNullable: true);

    migrationBuilder.AlterColumn<string>(
        name: "ActorPrincipalId",
        table: "AuthorizationChangeLogs",
        type: "character varying(50)",
        maxLength: 50,
        nullable: true,
        oldClrType: typeof(Guid),
        oldType: "uuid",
        oldNullable: true);
  }
}

using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ControlR.Web.Server.Data.Migrations;

/// <inheritdoc />
public partial class Add_PermissionReworkPhase2Schema : Migration
{
  /// <inheritdoc />
  protected override void Up(MigrationBuilder migrationBuilder)
  {
    migrationBuilder.AddColumn<Guid>(
        name: "CreatedByUserId",
        table: "PersonalAccessTokens",
        type: "uuid",
        nullable: true);

    migrationBuilder.AddColumn<DateTimeOffset>(
        name: "ExpiresAt",
        table: "PersonalAccessTokens",
        type: "timestamp with time zone",
        nullable: true);

    migrationBuilder.AddColumn<DateTimeOffset>(
        name: "RevokedAt",
        table: "PersonalAccessTokens",
        type: "timestamp with time zone",
        nullable: true);

    migrationBuilder.CreateTable(
        name: "AuthorizationChangeLogs",
        columns: table => new
        {
          Id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
          ActionType = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
          ActorPrincipalId = table.Column<Guid>(type: "uuid", nullable: true),
          ActorPrincipalType = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
          AfterJson = table.Column<string>(type: "text", nullable: true),
          BeforeJson = table.Column<string>(type: "text", nullable: true),
          CorrelationId = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
          IpAddress = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
          OwningTenantId = table.Column<Guid>(type: "uuid", nullable: true),
          TargetId = table.Column<Guid>(type: "uuid", nullable: true),
          TargetType = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
          CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP")
        },
        constraints: table =>
        {
          table.PrimaryKey("PK_AuthorizationChangeLogs", x => x.Id);
        });

    migrationBuilder.CreateTable(
        name: "DeviceGroups",
        columns: table => new
        {
          Id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
          Description = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
          Name = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
          CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
          TenantId = table.Column<Guid>(type: "uuid", nullable: false)
        },
        constraints: table =>
        {
          table.PrimaryKey("PK_DeviceGroups", x => x.Id);
          table.ForeignKey(
                    name: "FK_DeviceGroups_Tenants_TenantId",
                    column: x => x.TenantId,
                    principalTable: "Tenants",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
        });

    migrationBuilder.CreateTable(
        name: "LogonTokens",
        columns: table => new
        {
          Id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
          DeviceId = table.Column<Guid>(type: "uuid", nullable: false),
          ExpiresAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
          IsConsumed = table.Column<bool>(type: "boolean", nullable: false),
          Prefix = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
          SessionCorrelationId = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
          Token = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
          UserCorrelationId = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
          UserId = table.Column<Guid>(type: "uuid", nullable: false),
          CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
          TenantId = table.Column<Guid>(type: "uuid", nullable: false)
        },
        constraints: table =>
        {
          table.PrimaryKey("PK_LogonTokens", x => x.Id);
          table.ForeignKey(
                    name: "FK_LogonTokens_AspNetUsers_UserId",
                    column: x => x.UserId,
                    principalTable: "AspNetUsers",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
          table.ForeignKey(
                    name: "FK_LogonTokens_Devices_DeviceId",
                    column: x => x.DeviceId,
                    principalTable: "Devices",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
          table.ForeignKey(
                    name: "FK_LogonTokens_Tenants_TenantId",
                    column: x => x.TenantId,
                    principalTable: "Tenants",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
        });

    migrationBuilder.CreateTable(
        name: "PermissionAssignments",
        columns: table => new
        {
          Id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
          CreatedByPrincipalId = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
          CreatedByPrincipalType = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
          Effect = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
          IsEnabled = table.Column<bool>(type: "boolean", nullable: false),
          Notes = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
          OwningTenantId = table.Column<Guid>(type: "uuid", nullable: true),
          PermissionName = table.Column<string>(type: "character varying(150)", maxLength: 150, nullable: false),
          PrincipalId = table.Column<Guid>(type: "uuid", nullable: false),
          PrincipalKind = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
          ScopeId = table.Column<Guid>(type: "uuid", nullable: true),
          ScopeKind = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
          CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP")
        },
        constraints: table =>
        {
          table.PrimaryKey("PK_PermissionAssignments", x => x.Id);
        });

    migrationBuilder.CreateTable(
        name: "UserGroups",
        columns: table => new
        {
          Id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
          Description = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
          Name = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
          CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
          TenantId = table.Column<Guid>(type: "uuid", nullable: false)
        },
        constraints: table =>
        {
          table.PrimaryKey("PK_UserGroups", x => x.Id);
          table.ForeignKey(
                    name: "FK_UserGroups_Tenants_TenantId",
                    column: x => x.TenantId,
                    principalTable: "Tenants",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
        });

    migrationBuilder.CreateTable(
        name: "DeviceGroupMembers",
        columns: table => new
        {
          Id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
          DeviceGroupId = table.Column<Guid>(type: "uuid", nullable: false),
          DeviceId = table.Column<Guid>(type: "uuid", nullable: false),
          CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP")
        },
        constraints: table =>
        {
          table.PrimaryKey("PK_DeviceGroupMembers", x => x.Id);
          table.ForeignKey(
                    name: "FK_DeviceGroupMembers_DeviceGroups_DeviceGroupId",
                    column: x => x.DeviceGroupId,
                    principalTable: "DeviceGroups",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
          table.ForeignKey(
                    name: "FK_DeviceGroupMembers_Devices_DeviceId",
                    column: x => x.DeviceId,
                    principalTable: "Devices",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
        });

    migrationBuilder.CreateTable(
        name: "UserGroupMembers",
        columns: table => new
        {
          Id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
          UserGroupId = table.Column<Guid>(type: "uuid", nullable: false),
          UserId = table.Column<Guid>(type: "uuid", nullable: false),
          CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP")
        },
        constraints: table =>
        {
          table.PrimaryKey("PK_UserGroupMembers", x => x.Id);
          table.ForeignKey(
                    name: "FK_UserGroupMembers_AspNetUsers_UserId",
                    column: x => x.UserId,
                    principalTable: "AspNetUsers",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
          table.ForeignKey(
                    name: "FK_UserGroupMembers_UserGroups_UserGroupId",
                    column: x => x.UserGroupId,
                    principalTable: "UserGroups",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
        });

    migrationBuilder.CreateIndex(
        name: "IX_AuthorizationChangeLogs_CreatedAt",
        table: "AuthorizationChangeLogs",
        column: "CreatedAt");

    migrationBuilder.CreateIndex(
        name: "IX_AuthorizationChangeLogs_OwningTenantId",
        table: "AuthorizationChangeLogs",
        column: "OwningTenantId");

    migrationBuilder.CreateIndex(
        name: "IX_DeviceGroupMembers_DeviceGroupId_DeviceId",
        table: "DeviceGroupMembers",
        columns: new[] { "DeviceGroupId", "DeviceId" },
        unique: true);

    migrationBuilder.CreateIndex(
        name: "IX_DeviceGroupMembers_DeviceId",
        table: "DeviceGroupMembers",
        column: "DeviceId");

    migrationBuilder.CreateIndex(
        name: "IX_DeviceGroups_TenantId_Name",
        table: "DeviceGroups",
        columns: new[] { "TenantId", "Name" },
        unique: true);

    migrationBuilder.CreateIndex(
        name: "IX_LogonTokens_DeviceId",
        table: "LogonTokens",
        column: "DeviceId");

    migrationBuilder.CreateIndex(
        name: "IX_LogonTokens_TenantId",
        table: "LogonTokens",
        column: "TenantId");

    migrationBuilder.CreateIndex(
        name: "IX_LogonTokens_Token",
        table: "LogonTokens",
        column: "Token",
        unique: true);

    migrationBuilder.CreateIndex(
        name: "IX_LogonTokens_UserId",
        table: "LogonTokens",
        column: "UserId");

    migrationBuilder.CreateIndex(
        name: "IX_PermissionAssignments_PrincipalKind_PrincipalId",
        table: "PermissionAssignments",
        columns: new[] { "PrincipalKind", "PrincipalId" });

    migrationBuilder.CreateIndex(
        name: "IX_PermissionAssignments_ScopeKind_ScopeId",
        table: "PermissionAssignments",
        columns: new[] { "ScopeKind", "ScopeId" });

    migrationBuilder.CreateIndex(
        name: "IX_UserGroupMembers_UserGroupId_UserId",
        table: "UserGroupMembers",
        columns: new[] { "UserGroupId", "UserId" },
        unique: true);

    migrationBuilder.CreateIndex(
        name: "IX_UserGroupMembers_UserId",
        table: "UserGroupMembers",
        column: "UserId");

    migrationBuilder.CreateIndex(
        name: "IX_UserGroups_TenantId_Name",
        table: "UserGroups",
        columns: new[] { "TenantId", "Name" },
        unique: true);
  }

  /// <inheritdoc />
  protected override void Down(MigrationBuilder migrationBuilder)
  {
    migrationBuilder.DropTable(
        name: "AuthorizationChangeLogs");

    migrationBuilder.DropTable(
        name: "DeviceGroupMembers");

    migrationBuilder.DropTable(
        name: "LogonTokens");

    migrationBuilder.DropTable(
        name: "PermissionAssignments");

    migrationBuilder.DropTable(
        name: "UserGroupMembers");

    migrationBuilder.DropTable(
        name: "DeviceGroups");

    migrationBuilder.DropTable(
        name: "UserGroups");

    migrationBuilder.DropColumn(
        name: "CreatedByUserId",
        table: "PersonalAccessTokens");

    migrationBuilder.DropColumn(
        name: "ExpiresAt",
        table: "PersonalAccessTokens");

    migrationBuilder.DropColumn(
        name: "RevokedAt",
        table: "PersonalAccessTokens");
  }
}

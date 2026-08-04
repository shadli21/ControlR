using System;
using System.Linq;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Data.Enums;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace ControlR.Web.Server.Data.Migrations;

  /// <inheritdoc />
  public partial class Remove_Roles : Migration
  {
      /// <inheritdoc />
      protected override void Up(MigrationBuilder migrationBuilder)
      {
          // Backfill: Map each user's legacy role memberships to the corresponding preset's
          // permission assignments BEFORE the role tables are dropped. No-op on fresh databases
          // (AspNetUserRoles is empty during migration). For upgrades, it preserves existing access.
          //
          // Server-level roles (Server Administrator, Installer Key Manager) get ScopeKind.Server
          // with ScopeId = null and OwningTenantId = null, matching the API's Create behavior.
          // Tenant-level roles get ScopeKind.Tenant with ScopeId = the user's TenantId, which
          // the PermissionEvaluator.ScopeMatches method requires for tenant-scoped assignments.
          var backfillSql = $"""
              INSERT INTO "PermissionAssignments"
                ("{nameof(PermissionAssignment.PrincipalKind)}", "{nameof(PermissionAssignment.PrincipalId)}", "{nameof(PermissionAssignment.PermissionName)}", "{nameof(PermissionAssignment.Effect)}", "{nameof(PermissionAssignment.ScopeKind)}", "{nameof(PermissionAssignment.ScopeId)}", "{nameof(PermissionAssignment.IsEnabled)}", "{nameof(PermissionAssignment.OwningTenantId)}", "{nameof(PermissionAssignment.CreatedByPrincipalType)}", "{nameof(PermissionAssignment.CreatedByPrincipalId)}")
              SELECT DISTINCT '{PermissionPrincipalKind.User}', ur."UserId", rp."PermissionName", '{PermissionEffect.Allow}',
                CASE
                  WHEN r."Name" IN ('Server Administrator', 'Installer Key Manager') THEN '{PermissionScopeKind.Server}'
                  ELSE '{PermissionScopeKind.Tenant}'
                END,
                CASE
                  WHEN r."Name" IN ('Server Administrator', 'Installer Key Manager') THEN NULL
                  ELSE u."TenantId"
                END,
                true,
                CASE
                  WHEN r."Name" IN ('Server Administrator', 'Installer Key Manager') THEN NULL
                  ELSE u."TenantId"
                END,
                'system', CAST(ur."UserId" AS text)
              FROM "AspNetUserRoles" ur
              INNER JOIN "AspNetRoles" r ON ur."RoleId" = r."Id"
              INNER JOIN "AspNetUsers" u ON ur."UserId" = u."Id"
              INNER JOIN (
                VALUES
                  ('Server Administrator', '{PermissionNames.ServerAdmin}'),
                  ('Server Administrator', '{PermissionNames.ServerAlertsRead}'),
                  ('Server Administrator', '{PermissionNames.ServerAlertsWrite}'),
                  ('Server Administrator', '{PermissionNames.ServerTelemetryRead}'),
                  ('Server Administrator', '{PermissionNames.ServerServiceAccountsRead}'),
                  ('Server Administrator', '{PermissionNames.ServerServiceAccountsWrite}'),
                  ('Server Administrator', '{PermissionNames.ServerServiceAccountsRotateCredentials}'),
                  ('Tenant Administrator', '{PermissionNames.TenantRead}'),
                  ('Tenant Administrator', '{PermissionNames.TenantSettingsRead}'),
                  ('Tenant Administrator', '{PermissionNames.TenantSettingsWrite}'),
                  ('Tenant Administrator', '{PermissionNames.TenantUsersRead}'),
                  ('Tenant Administrator', '{PermissionNames.TenantUsersWrite}'),
                  ('Tenant Administrator', '{PermissionNames.TenantUsersDelete}'),
                  ('Tenant Administrator', '{PermissionNames.TenantUserGroupsRead}'),
                  ('Tenant Administrator', '{PermissionNames.TenantUserGroupsWrite}'),
                  ('Tenant Administrator', '{PermissionNames.UserGroupAssignUsers}'),
                  ('Tenant Administrator', '{PermissionNames.TenantDeviceGroupsRead}'),
                  ('Tenant Administrator', '{PermissionNames.TenantDeviceGroupsWrite}'),
                  ('Tenant Administrator', '{PermissionNames.DeviceGroupAssignDevices}'),
                  ('Tenant Administrator', '{PermissionNames.TenantCustomersRead}'),
                  ('Tenant Administrator', '{PermissionNames.TenantCustomersWrite}'),
                  ('Tenant Administrator', '{PermissionNames.TenantTagsWrite}'),
                  ('Tenant Administrator', '{PermissionNames.TenantPermissionsRead}'),
                  ('Tenant Administrator', '{PermissionNames.TenantPermissionsWrite}'),
                  ('Tenant Administrator', '{PermissionNames.TenantPermissionsDeny}'),
                  ('Tenant Administrator', '{PermissionNames.PersonalAccessTokenSelfRead}'),
                  ('Tenant Administrator', '{PermissionNames.PersonalAccessTokenSelfWrite}'),
                  ('Tenant Administrator', '{PermissionNames.PersonalAccessTokenOthersRead}'),
                  ('Tenant Administrator', '{PermissionNames.PersonalAccessTokenOthersWrite}'),
                  ('Tenant Administrator', '{PermissionNames.ServiceAccountRead}'),
                  ('Tenant Administrator', '{PermissionNames.ServiceAccountWrite}'),
                  ('Tenant Administrator', '{PermissionNames.ServiceAccountRotateCredentials}'),
                  ('Tenant Administrator', '{PermissionNames.InstallerKeyRead}'),
                  ('Tenant Administrator', '{PermissionNames.InstallerKeyWrite}'),
                  ('Tenant Administrator', '{PermissionNames.InstallerKeyManageAll}'),
                  ('Tenant Administrator', '{PermissionNames.AgentInstall}'),
                  ('Installer Key Manager', '{PermissionNames.InstallerKeyRead}'),
                  ('Installer Key Manager', '{PermissionNames.InstallerKeyWrite}'),
                  ('Installer Key Manager', '{PermissionNames.AgentInstall}'),
                  ('Device Superuser', '{PermissionNames.DeviceRead}'),
                  ('Device Superuser', '{PermissionNames.DeviceDelete}'),
                  ('Device Superuser', '{PermissionNames.DeviceAliasWrite}'),
                  ('Device Superuser', '{PermissionNames.DeviceTagsRead}'),
                  ('Device Superuser', '{PermissionNames.DeviceTagsWrite}'),
                  ('Device Superuser', '{PermissionNames.DeviceDesktopPreviewRead}'),
                  ('Device Superuser', '{PermissionNames.DeviceLogsRead}'),
                  ('Device Superuser', '{PermissionNames.DeviceRemoteControlConnect}'),
                  ('Device Superuser', '{PermissionNames.DeviceRemoteControlInteract}'),
                  ('Device Superuser', '{PermissionNames.DeviceRemoteControlBlockInput}'),
                  ('Device Superuser', '{PermissionNames.DeviceRemoteControlElevatedDesktop}'),
                  ('Device Superuser', '{PermissionNames.DeviceCtrlAltDelSend}'),
                  ('Device Superuser', '{PermissionNames.DeviceClipboardRead}'),
                  ('Device Superuser', '{PermissionNames.DeviceClipboardWrite}'),
                  ('Device Superuser', '{PermissionNames.DeviceChatSend}'),
                  ('Device Superuser', '{PermissionNames.DeviceFileSystemRead}'),
                  ('Device Superuser', '{PermissionNames.DeviceFileSystemWrite}'),
                  ('Device Superuser', '{PermissionNames.DeviceFileSystemDelete}'),
                  ('Device Superuser', '{PermissionNames.DeviceFileSystemTransferUpload}'),
                  ('Device Superuser', '{PermissionNames.DeviceFileSystemTransferDownload}'),
                  ('Device Superuser', '{PermissionNames.DeviceTerminalUse}'),
                  ('Device Superuser', '{PermissionNames.DeviceLogonTokenCreate}'),
                  ('Device Superuser', '{PermissionNames.DeviceWakeSend}'),
                  ('Device Superuser', '{PermissionNames.DevicePowerManage}'),
                  ('Device Superuser', '{PermissionNames.DeviceAgentUpdate}'),
                  ('Agent Installer', '{PermissionNames.AgentInstall}')
              ) AS rp("RoleName", "PermissionName") ON r."Name" = rp."RoleName";
              """;
          migrationBuilder.Sql(backfillSql);

          migrationBuilder.DropTable(
              name: "AspNetRoleClaims");

          migrationBuilder.DropTable(
              name: "AspNetUserRoles");

          migrationBuilder.DropTable(
              name: "AspNetRoles");
      }

      /// <inheritdoc />
      protected override void Down(MigrationBuilder migrationBuilder)
      {
          migrationBuilder.CreateTable(
              name: "AspNetRoles",
              columns: table => new
              {
                  Id = table.Column<Guid>(type: "uuid", nullable: false),
                  ConcurrencyStamp = table.Column<string>(type: "text", nullable: true),
                  Name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                  NormalizedName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true)
              },
              constraints: table =>
              {
                  table.PrimaryKey("PK_AspNetRoles", x => x.Id);
              });

          migrationBuilder.CreateTable(
              name: "AspNetRoleClaims",
              columns: table => new
              {
                  Id = table.Column<int>(type: "integer", nullable: false)
                      .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                  ClaimType = table.Column<string>(type: "text", nullable: true),
                  ClaimValue = table.Column<string>(type: "text", nullable: true),
                  RoleId = table.Column<Guid>(type: "uuid", nullable: false)
              },
              constraints: table =>
              {
                  table.PrimaryKey("PK_AspNetRoleClaims", x => x.Id);
                  table.ForeignKey(
                      name: "FK_AspNetRoleClaims_AspNetRoles_RoleId",
                      column: x => x.RoleId,
                      principalTable: "AspNetRoles",
                      principalColumn: "Id",
                      onDelete: ReferentialAction.Cascade);
              });

          migrationBuilder.CreateTable(
              name: "AspNetUserRoles",
              columns: table => new
              {
                  UserId = table.Column<Guid>(type: "uuid", nullable: false),
                  RoleId = table.Column<Guid>(type: "uuid", nullable: false)
              },
              constraints: table =>
              {
                  table.PrimaryKey("PK_AspNetUserRoles", x => new { x.UserId, x.RoleId });
                  table.ForeignKey(
                      name: "FK_AspNetUserRoles_AspNetRoles_RoleId",
                      column: x => x.RoleId,
                      principalTable: "AspNetRoles",
                      principalColumn: "Id",
                      onDelete: ReferentialAction.Cascade);
                  table.ForeignKey(
                      name: "FK_AspNetUserRoles_AspNetUsers_UserId",
                      column: x => x.UserId,
                      principalTable: "AspNetUsers",
                      principalColumn: "Id",
                      onDelete: ReferentialAction.Cascade);
              });

          migrationBuilder.InsertData(
              table: "AspNetRoles",
              columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
              values: new object[,]
              {
                  { new Guid("8ad85243-aa78-7539-0bf7-0cd6f27bcaa5"), "d6b798d2-a7f0-492b-a6ad-7eba9b1e3beb", "Server Administrator", "SERVER ADMINISTRATOR" },
                  { new Guid("963de2cb-fc55-43cd-11ac-dd6261c81bd8"), "a7e1a339-19c3-4d44-97e3-239636906a45", "Installer Key Manager", "INSTALLER KEY MANAGER" },
                  { new Guid("98aecfed-4095-42fd-e4b8-556d5b723bb6"), "0b692fe4-63e1-4a99-b021-4fc48ed81f4c", "Device Superuser", "DEVICE SUPERUSER" },
                  { new Guid("dde33610-89dc-e6a4-8d8a-33f3823a180e"), "ccfd2843-8a06-43d4-9bf3-6110b4e65900", "Agent Installer", "AGENT INSTALLER" },
                  { new Guid("ed0dddf2-c2b2-4160-9ece-4a9e03b2e828"), "b23bdf83-ecc8-4ca2-ba24-dc1780bfefc6", "Tenant Administrator", "TENANT ADMINISTRATOR" }
              });

          migrationBuilder.CreateIndex(
              name: "IX_AspNetRoleClaims_RoleId",
              table: "AspNetRoleClaims",
              column: "RoleId");

          migrationBuilder.CreateIndex(
              name: "RoleNameIndex",
              table: "AspNetRoles",
              column: "NormalizedName",
              unique: true);

          migrationBuilder.CreateIndex(
              name: "IX_AspNetUserRoles_RoleId",
              table: "AspNetUserRoles",
              column: "RoleId");
      }
  }

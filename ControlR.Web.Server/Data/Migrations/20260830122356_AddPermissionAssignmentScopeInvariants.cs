using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ControlR.Web.Server.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddPermissionAssignmentScopeInvariants : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddCheckConstraint(
                name: "CA_PermissionAssignments_NonServer_OwningTenant",
                table: "PermissionAssignments",
                sql: "\"ScopeKind\" IN ('Unknown', 'Server') OR \"OwningTenantId\" IS NOT NULL");

            migrationBuilder.AddCheckConstraint(
                name: "CA_PermissionAssignments_ScopeKind_ScopeId",
                table: "PermissionAssignments",
                sql: "\"ScopeKind\" NOT IN ('Tenant', 'Device', 'DeviceGroup', 'CustomerTenant', 'UserGroup') OR \"ScopeId\" IS NOT NULL");

            migrationBuilder.AddCheckConstraint(
                name: "CA_PermissionAssignments_Server_NullScope",
                table: "PermissionAssignments",
                sql: "\"ScopeKind\" <> 'Server' OR (\"ScopeId\" IS NULL AND \"OwningTenantId\" IS NULL)");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CA_PermissionAssignments_NonServer_OwningTenant",
                table: "PermissionAssignments");

            migrationBuilder.DropCheckConstraint(
                name: "CA_PermissionAssignments_ScopeKind_ScopeId",
                table: "PermissionAssignments");

            migrationBuilder.DropCheckConstraint(
                name: "CA_PermissionAssignments_Server_NullScope",
                table: "PermissionAssignments");
        }
    }
}

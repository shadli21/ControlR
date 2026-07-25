using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ControlR.Web.Server.Data.Migrations;

/// <inheritdoc />
public partial class Add_Customers : Migration
{
  /// <inheritdoc />
  protected override void Up(MigrationBuilder migrationBuilder)
  {
    migrationBuilder.AddColumn<Guid>(
        name: "CustomerId",
        table: "Devices",
        type: "uuid",
        nullable: true);

    migrationBuilder.CreateTable(
        name: "Customers",
        columns: table => new
        {
          Id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
          Description = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
          Name = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
          Notes = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
          CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
          TenantId = table.Column<Guid>(type: "uuid", nullable: false)
        },
        constraints: table =>
        {
          table.PrimaryKey("PK_Customers", x => x.Id);
          table.ForeignKey(
                    name: "FK_Customers_Tenants_TenantId",
                    column: x => x.TenantId,
                    principalTable: "Tenants",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
        });

    migrationBuilder.CreateIndex(
        name: "IX_Devices_CustomerId",
        table: "Devices",
        column: "CustomerId");

    migrationBuilder.CreateIndex(
        name: "IX_Customers_TenantId_Name",
        table: "Customers",
        columns: new[] { "TenantId", "Name" },
        unique: true);

    migrationBuilder.AddForeignKey(
        name: "FK_Devices_Customers_CustomerId",
        table: "Devices",
        column: "CustomerId",
        principalTable: "Customers",
        principalColumn: "Id",
        onDelete: ReferentialAction.SetNull);
  }

  /// <inheritdoc />
  protected override void Down(MigrationBuilder migrationBuilder)
  {
    migrationBuilder.DropForeignKey(
        name: "FK_Devices_Customers_CustomerId",
        table: "Devices");

    migrationBuilder.DropTable(
        name: "Customers");

    migrationBuilder.DropIndex(
        name: "IX_Devices_CustomerId",
        table: "Devices");

    migrationBuilder.DropColumn(
        name: "CustomerId",
        table: "Devices");
  }
}

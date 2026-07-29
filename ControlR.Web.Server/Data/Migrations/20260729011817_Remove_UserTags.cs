using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ControlR.Web.Server.Data.Migrations;

/// <inheritdoc />
public partial class Remove_UserTags : Migration
{
  /// <inheritdoc />
  protected override void Up(MigrationBuilder migrationBuilder)
  {
    migrationBuilder.DropTable(
        name: "AppUserTag");
  }

  /// <inheritdoc />
  protected override void Down(MigrationBuilder migrationBuilder)
  {
    migrationBuilder.CreateTable(
        name: "AppUserTag",
        columns: table => new
        {
          TagsId = table.Column<Guid>(type: "uuid", nullable: false),
          UsersId = table.Column<Guid>(type: "uuid", nullable: false)
        },
        constraints: table =>
        {
          table.PrimaryKey("PK_AppUserTag", x => new { x.TagsId, x.UsersId });
          table.ForeignKey(
                    name: "FK_AppUserTag_AspNetUsers_UsersId",
                    column: x => x.UsersId,
                    principalTable: "AspNetUsers",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
          table.ForeignKey(
                    name: "FK_AppUserTag_Tags_TagsId",
                    column: x => x.TagsId,
                    principalTable: "Tags",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
        });

    migrationBuilder.CreateIndex(
        name: "IX_AppUserTag_UsersId",
        table: "AppUserTag",
        column: "UsersId");
  }
}

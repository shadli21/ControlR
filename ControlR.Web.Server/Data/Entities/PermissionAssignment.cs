using System.ComponentModel.DataAnnotations;
using ControlR.Web.Server.Data.Entities.Bases;
using ControlR.Web.Server.Data.Enums;

namespace ControlR.Web.Server.Data.Entities;

public class PermissionAssignment : EntityBase
{
  [StringLength(50)]
  public string? CreatedByPrincipalId { get; set; }

  [StringLength(50)]
  public string? CreatedByPrincipalType { get; set; }

  public PermissionEffect Effect { get; set; }

  public bool IsEnabled { get; set; } = true;

  [StringLength(500)]
  public string? Notes { get; set; }

  public Guid? OwningTenantId { get; set; }

  [StringLength(150)]
  public required string PermissionName { get; set; }

  public Guid PrincipalId { get; set; }

  public PermissionPrincipalKind PrincipalKind { get; set; }

  public Guid? ScopeId { get; set; }

  public PermissionScopeKind ScopeKind { get; set; }
}

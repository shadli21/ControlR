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

  /// <summary>
  /// Creates a new grant row enforcing the assignment invariants: server-scoped rows carry
  /// no ScopeId or OwningTenantId; all other rows keep the given scope target and are owned
  /// by the granting tenant.
  /// </summary>
  public static PermissionAssignment CreateGrant(
    PermissionPrincipalKind principalKind,
    Guid principalId,
    string permissionName,
    PermissionScopeKind scopeKind,
    Guid? scopeId,
    Guid? owningTenantId,
    string createdByPrincipalType,
    string? createdByPrincipalId,
    PermissionEffect effect = PermissionEffect.Allow,
    string? notes = null) =>
    new()
    {
      PrincipalKind = principalKind,
      PrincipalId = principalId,
      PermissionName = permissionName,
      Effect = effect,
      ScopeKind = scopeKind,
      ScopeId = scopeKind == PermissionScopeKind.Server ? null : scopeId,
      IsEnabled = true,
      OwningTenantId = scopeKind == PermissionScopeKind.Server ? null : owningTenantId,
      CreatedByPrincipalType = createdByPrincipalType,
      CreatedByPrincipalId = createdByPrincipalId,
      Notes = notes
    };
}

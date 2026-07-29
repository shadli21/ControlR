using System.ComponentModel.DataAnnotations;
using ControlR.Libraries.Api.Contracts.Enums;

namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

public record CreatePermissionAssignmentRequestDto(
  PermissionPrincipalKind PrincipalKind,

  Guid PrincipalId,

  [property: Required]
  [property: StringLength(150, MinimumLength = 1)]
  string PermissionName,

  PermissionEffect Effect,

  PermissionScopeKind ScopeKind,

  Guid? ScopeId,

  [property: StringLength(500)]
  string? Notes);

public record PermissionAssignmentDto(
  Guid Id,
  PermissionPrincipalKind PrincipalKind,
  Guid PrincipalId,
  string PermissionName,
  PermissionEffect Effect,
  PermissionScopeKind ScopeKind,
  Guid? ScopeId,
  string? Notes,
  bool IsEnabled,
  DateTimeOffset CreatedAt);

public record UpdatePermissionAssignmentRequestDto(
  [property: Required]
  [property: StringLength(150, MinimumLength = 1)]
  string PermissionName,

  PermissionEffect Effect,

  PermissionScopeKind ScopeKind,

  Guid? ScopeId,

  [property: StringLength(500)]
  string? Notes,

  bool IsEnabled);

public record EffectivePermissionQueryRequestDto(
  PermissionPrincipalKind PrincipalKind,

  Guid PrincipalId,

  [property: Required]
  [property: StringLength(150, MinimumLength = 1)]
  string PermissionName,

  PermissionScopeKind ScopeKind,

  Guid? ScopeId);

public record EffectivePermissionQueryResponseDto(
  bool IsAllowed,
  string? DenyReason);

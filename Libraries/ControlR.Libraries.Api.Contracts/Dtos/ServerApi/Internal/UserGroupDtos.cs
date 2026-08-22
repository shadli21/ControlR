using System.ComponentModel.DataAnnotations;

namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

public record CreateUserGroupRequestDto(
  [property: Required]
  [property: StringLength(100, MinimumLength = 1)]
  string Name,

  [property: StringLength(500)]
  string? Description);

public record UpdateUserGroupRequestDto(
  [property: Required]
  [property: StringLength(100, MinimumLength = 1)]
  string Name,

  [property: StringLength(500)]
  string? Description);

public record UserGroupMemberDto(
  Guid UserId,
  string UserName,
  string? DisplayName,
  DateTimeOffset? LastLogin);

public record UserGroupDto(
  Guid Id,
  string Name,
  string? Description,
  DateTimeOffset CreatedAt,
  int MemberCount);

public record UserGroupDetailDto(
  Guid Id,
  string Name,
  string? Description,
  DateTimeOffset CreatedAt,
  IReadOnlyList<UserGroupMemberDto> Members);

public record AddUserGroupMembersRequestDto(
  [property: Required]
  IReadOnlyList<Guid> UserIds);

public record RemoveUserGroupMembersRequestDto(
  [property: Required]
  IReadOnlyList<Guid> UserIds);

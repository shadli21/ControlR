using System.ComponentModel.DataAnnotations;
using ControlR.Libraries.Api.Contracts.Enums;
using ControlR.Web.Server.Data.Entities.Bases;

namespace ControlR.Web.Server.Data.Entities;

public class PersonalAccessToken : EntityBase
{
  public Guid? CreatedByUserId { get; set; }
  public DateTimeOffset? ExpiresAt { get; set; }

  [Required]
  [StringLength(256)]
  public required string HashedKey { get; set; }
  public DateTimeOffset? LastUsed { get; set; }

  [Required]
  [StringLength(256)]
  public required string Name { get; set; }

  /// <summary>
  /// How this token is evaluated during permission checks. Explicitly set at creation;
  /// never inferred from scope rows.
  /// </summary>
  public PersonalAccessTokenPermissionMode PermissionMode { get; set; } = PersonalAccessTokenPermissionMode.Restricted;
  public DateTimeOffset? RevokedAt { get; set; }
  public AppUser? User { get; set; }

  [Required]
  public required Guid UserId { get; set; }
}

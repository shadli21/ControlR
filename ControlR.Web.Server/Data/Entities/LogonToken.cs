using System.ComponentModel.DataAnnotations;
using ControlR.Web.Server.Data.Entities.Bases;

namespace ControlR.Web.Server.Data.Entities;

public class LogonToken : TenantEntityBase
{
  public IReadOnlyList<int>? AllowedDesktopSessionIds { get; set; }
  public Device? Device { get; set; }
  public Guid DeviceId { get; set; }
  public DateTimeOffset ExpiresAt { get; set; }
  public bool IsConsumed { get; set; }

  [StringLength(32)]
  public string? Prefix { get; set; }

  [StringLength(100)]
  public string? SessionCorrelationId { get; set; }

  [StringLength(256)]
  public required string Token { get; set; }
  public AppUser? User { get; set; }

  [StringLength(100)]
  public string? UserCorrelationId { get; set; }
  public Guid UserId { get; set; }
}

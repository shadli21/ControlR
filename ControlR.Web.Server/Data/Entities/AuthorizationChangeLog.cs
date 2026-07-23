using System.ComponentModel.DataAnnotations;
using ControlR.Web.Server.Data.Entities.Bases;

namespace ControlR.Web.Server.Data.Entities;

public class AuthorizationChangeLog : EntityBase
{
  [StringLength(100)]
  public required string ActionType { get; set; }

  [StringLength(50)]
  public string? ActorPrincipalId { get; set; }

  [StringLength(50)]
  public required string ActorPrincipalType { get; set; }

  public string? AfterJson { get; set; }

  public string? BeforeJson { get; set; }

  [StringLength(100)]
  public string? CorrelationId { get; set; }

  [StringLength(64)]
  public string? IpAddress { get; set; }

  public Guid? OwningTenantId { get; set; }

  [StringLength(100)]
  public string? TargetId { get; set; }

  [StringLength(100)]
  public required string TargetType { get; set; }
}

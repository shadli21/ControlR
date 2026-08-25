using System.ComponentModel.DataAnnotations;
using ControlR.Web.Server.Data.Entities.Bases;

namespace ControlR.Web.Server.Data.Entities;

public class Customer : TenantEntityBase
{
  [StringLength(500)]
  public string? Description { get; set; }

  [StringLength(100)]
  public required string Name { get; set; }

  [StringLength(500)]
  public string? Notes { get; set; }
}

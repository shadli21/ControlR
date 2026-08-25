using ControlR.Web.Server.Data.Entities.Bases;

namespace ControlR.Web.Server.Data.Entities;

public class DeviceGroupMember : EntityBase
{
  public Device? Device { get; set; }
  public DeviceGroup? DeviceGroup { get; set; }
  public Guid DeviceGroupId { get; set; }
  public Guid DeviceId { get; set; }
}

using ControlR.Web.Server.Data.Entities.Bases;

namespace ControlR.Web.Server.Data.Entities;

public class UserGroupMember : EntityBase
{
  public AppUser? User { get; set; }
  public UserGroup? UserGroup { get; set; }
  public Guid UserGroupId { get; set; }
  public Guid UserId { get; set; }
}

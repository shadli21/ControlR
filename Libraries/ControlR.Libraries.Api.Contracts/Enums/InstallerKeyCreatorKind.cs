using System.Runtime.Serialization;

namespace ControlR.Libraries.Api.Contracts.Enums;

/// <summary>
/// The kind of principal that created an <c>AgentInstallerKey</c>. This governs ownership and
/// the re-authorization path used when a device re-registers with an existing key: keys created
/// by a <see cref="User"/> are re-checked against that user's current authority, while keys
/// created by a service account are authorized by the key itself (automated provisioning).
/// </summary>
[DataContract]
public enum InstallerKeyCreatorKind
{
  [EnumMember]
  User = 0,
  [EnumMember]
  ServerServiceAccount = 1,
  [EnumMember]
  TenantServiceAccount = 2
}

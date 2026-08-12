using System.Text.Json.Serialization;

namespace ControlR.Libraries.Api.Contracts.Enums;

/// <summary>
/// Distinguishes server-scoped (global) service accounts from tenant-scoped service accounts.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum ServiceAccountKind
{
  Tenant,
  Server
}

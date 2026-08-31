using System.Text.Json.Serialization;

namespace ControlR.Libraries.Api.Contracts.Enums;

/// <summary>
/// Determines how a server service account is evaluated during permission checks.
/// Persisted on the account so the mode is never inferred from the presence or absence of assignment rows.
/// Tenant service accounts are not governed by this mode and never bypass.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum ServiceAccountAccessMode
{
  /// <summary>
  /// The account evaluates its assignment rows normally. Zero rows deny everything.
  /// </summary>
  Restricted,

  /// <summary>
  /// The account bypasses permission evaluation with full server access.
  /// </summary>
  Unrestricted
}

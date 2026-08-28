using System.Text.Json.Serialization;

namespace ControlR.Libraries.Api.Contracts.Enums;

/// <summary>
/// Determines how a personal access token is evaluated during permission checks.
/// Persisted on the token so the mode is never inferred from the presence or absence of scope rows.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum PersonalAccessTokenPermissionMode
{
  /// <summary>
  /// The token evaluates only its own scope rows. Zero rows deny everything.
  /// </summary>
  Restricted,

  /// <summary>
  /// The token evaluates as its owning user. Scope rows are not meaningful.
  /// </summary>
  InheritOwner,
}

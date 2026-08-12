using System.Text.Json;
using System.Text.Json.Serialization;

namespace ControlR.Web.Server.Services.Authorization;

/// <summary>
/// Factory for creating <see cref="AuthorizationChangeLog"/> entries with typed,
/// properly-serialized before/after snapshots. Eliminates hand-interpolated JSON strings.
/// </summary>
public static class AuthorizationChangeLogFactory
{
  private static readonly JsonSerializerOptions _serializerOptions = new()
  {
    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    Converters = { new JsonStringEnumConverter() }
  };

  public static AuthorizationChangeLog Create(
    string actionType,
    string actorPrincipalType,
    Guid? actorPrincipalId,
    string targetType,
    Guid? targetId,
    Guid? owningTenantId,
    object? before = null,
    object? after = null)
  {
    return new AuthorizationChangeLog
    {
      ActionType = actionType,
      ActorPrincipalType = actorPrincipalType,
      ActorPrincipalId = NormalizeEmptyGuid(actorPrincipalId),
      TargetType = targetType,
      TargetId = NormalizeEmptyGuid(targetId),
      OwningTenantId = owningTenantId,
      BeforeJson = before is not null ? JsonSerializer.Serialize(before, _serializerOptions) : null,
      AfterJson = after is not null ? JsonSerializer.Serialize(after, _serializerOptions) : null
    };
  }

  /// <summary>
  /// Normalizes a <see cref="Guid.Empty"/> to <see langword="null"/> so an unresolved
  /// (e.g. pre-save) entity ID can never be written to the audit log as a literal
  /// <c>00000000-0000-0000-0000-000000000000</c>.
  /// </summary>
  private static Guid? NormalizeEmptyGuid(Guid? value) =>
    value is { } nonNull && nonNull != Guid.Empty ? nonNull : null;
}

using System.Text.Json;

namespace ControlR.Web.Server.Services.Authorization;

/// <summary>
/// Factory for creating <see cref="AuthorizationChangeLog"/> entries with typed,
/// properly-serialized before/after snapshots. Eliminates hand-interpolated JSON strings.
/// </summary>
public static class AuthorizationChangeLogEntry
{
  private static readonly JsonSerializerOptions _serializerOptions = new()
  {
    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
  };

  public static AuthorizationChangeLog Create(
    string actionType,
    string actorPrincipalType,
    string? actorPrincipalId,
    string targetType,
    string? targetId,
    Guid? owningTenantId,
    object? before = null,
    object? after = null)
  {
    return new AuthorizationChangeLog
    {
      ActionType = actionType,
      ActorPrincipalType = actorPrincipalType,
      ActorPrincipalId = actorPrincipalId,
      TargetType = targetType,
      TargetId = targetId,
      OwningTenantId = owningTenantId,
      BeforeJson = before is not null ? JsonSerializer.Serialize(before, _serializerOptions) : null,
      AfterJson = after is not null ? JsonSerializer.Serialize(after, _serializerOptions) : null
    };
  }
}

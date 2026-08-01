using System.Text.Json;
using System.Text.Json.Serialization;

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
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    Converters = { new JsonStringEnumConverter() }
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

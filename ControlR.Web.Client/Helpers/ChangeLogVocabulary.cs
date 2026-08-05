using System.Reflection;

namespace ControlR.Web.Client.Helpers;

/// <summary>
/// Authorization change log filter vocabularies, reflected once from the shared contract
/// constants so new action/target types appear automatically as they are added.
/// </summary>
public static class ChangeLogVocabulary
{
  public static IReadOnlyList<string> ActionTypes { get; } =
    GetConstValues(typeof(AuthorizationChangeLogActions));

  public static IReadOnlyList<string> TargetTypes { get; } =
    GetConstValues(typeof(AuthorizationChangeLogTargetTypes));

  private static IReadOnlyList<string> GetConstValues(Type type) =>
    type
      .GetFields(BindingFlags.Public | BindingFlags.Static)
      .Where(field => field.IsLiteral && field.FieldType == typeof(string))
      .Select(field => field.GetRawConstantValue() as string)
      .OfType<string>()
      .Order()
      .ToList();
}

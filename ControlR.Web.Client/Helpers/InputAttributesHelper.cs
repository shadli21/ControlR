namespace ControlR.Web.Client.Helpers;

/// <summary>
/// HTML input attributes that suppress browser autofill and password manager suggestions.
/// Pass to MudBlazor <c>UserAttributes</c> on fields that should not trigger autofill.
/// </summary>
public static class InputAttributesHelper
{
  public static Dictionary<string, object> SuppressAutofill { get; } = new()
  {
    ["autocomplete"] = "off",
    ["autocapitalize"] = "off",
    ["spellcheck"] = "false"
  };
}

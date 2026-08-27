namespace ControlR.Web.Client.Components.Dialogs;

public sealed record CreateServiceAccountCredentialDialogResult(string Name, DateTimeOffset? ExpiresAt);

public partial class CreateServiceAccountCredentialDialog : ComponentBase
{
  private DateTimeOffset? _expiresAt;
  private string _name = string.Empty;

  [CascadingParameter]
  public required IMudDialogInstance MudDialog { get; init; }

  private void Cancel() => MudDialog.Cancel();

  private void Save()
  {
    var name = _name.Trim();
    var result = new CreateServiceAccountCredentialDialogResult(name, _expiresAt);
    MudDialog.Close(DialogResult.Ok(result));
  }
}

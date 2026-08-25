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
    MudDialog.Close(DialogResult.Ok(new CreateServiceAccountCredentialDialogResult(_name.Trim(), _expiresAt)));
  }
}

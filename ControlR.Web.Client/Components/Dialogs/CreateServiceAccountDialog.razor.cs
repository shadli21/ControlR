namespace ControlR.Web.Client.Components.Dialogs;

public sealed record CreateServiceAccountDialogResult(
  string Name,
  string? Description,
  string? CredentialName,
  DateTimeOffset? CredentialExpiresAt);

public partial class CreateServiceAccountDialog : ComponentBase
{
  private bool _createCredential = true;
  private DateTimeOffset? _credentialExpiresAt;
  private string _credentialName = "Initial Credential";
  private string _description = string.Empty;
  private string _name = string.Empty;

  [Parameter]
  public required bool CanIssueCredential { get; init; }

  [CascadingParameter]
  public required IMudDialogInstance MudDialog { get; init; }

  [Parameter]
  public required string RotatePermissionLabel { get; init; }

  private bool CanSave =>
    !string.IsNullOrWhiteSpace(_name) &&
    (!CanIssueCredential || !_createCredential || !string.IsNullOrWhiteSpace(_credentialName));

  private void Cancel() => MudDialog.Cancel();

  private void Save()
  {
    var issueCredential = CanIssueCredential && _createCredential;

    MudDialog.Close(DialogResult.Ok(new CreateServiceAccountDialogResult(
      _name.Trim(),
      string.IsNullOrWhiteSpace(_description) ? null : _description.Trim(),
      issueCredential ? _credentialName.Trim() : null,
      issueCredential ? _credentialExpiresAt : null)));
  }
}

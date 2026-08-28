namespace ControlR.Web.Client.Components.Dialogs;

public sealed record CreateServiceAccountDialogResult(
  string Name,
  string? Description,
  string? CredentialName,
  DateTimeOffset? CredentialExpiresAt,
  ServiceAccountAccessMode AccessMode);

public partial class CreateServiceAccountDialog : ComponentBase
{
  private ServiceAccountAccessMode _accessMode = ServiceAccountAccessMode.Restricted;
  private bool _createCredential = true;
  private DateTimeOffset? _credentialExpiresAt;
  private string _credentialName = "Initial Credential";
  private string _description = string.Empty;
  private string _name = string.Empty;

  [Parameter]
  public required bool CanGrantUnrestricted { get; init; }

  [Parameter]
  public required bool CanIssueCredential { get; init; }

  [Parameter]
  public bool IsServerAccount { get; init; }

  [CascadingParameter]
  public required IMudDialogInstance MudDialog { get; init; }

  [Parameter]
  public required string RotatePermissionLabel { get; init; }

  private bool CanSave =>
    !string.IsNullOrWhiteSpace(_name) &&
    (!CanIssueCredential || !_createCredential || !string.IsNullOrWhiteSpace(_credentialName)) &&
    (_accessMode != ServiceAccountAccessMode.Unrestricted || CanGrantUnrestricted);

  private void Cancel() => MudDialog.Cancel();

  private void Save()
  {
    if (_accessMode == ServiceAccountAccessMode.Unrestricted && !CanGrantUnrestricted)
    {
      MudDialog.Close(DialogResult.Cancel());
      return;
    }

    var issueCredential = CanIssueCredential && _createCredential;

    var name = _name.Trim();
    var description = string.IsNullOrWhiteSpace(_description) ? null : _description.Trim();
    var credentialName = issueCredential ? _credentialName.Trim() : null;
    var credentialExpiresAt = issueCredential ? _credentialExpiresAt : null;

    var result = new CreateServiceAccountDialogResult(
      name,
      description,
      credentialName,
      credentialExpiresAt,
      _accessMode);
      
    MudDialog.Close(DialogResult.Ok(result));
  }
}

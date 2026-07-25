namespace ControlR.Web.Client.Components.Dialogs;

public sealed record EditGroupDialogResult(string Name, string? Description);

public partial class EditGroupDialog : ComponentBase
{
  private string _description = string.Empty;
  private string _name = string.Empty;

  [Parameter]
  public string? Description { get; set; }

  [CascadingParameter]
  public required IMudDialogInstance MudDialog { get; init; }

  [Parameter]
  public required string Name { get; set; }

  protected override void OnInitialized()
  {
    _name = Name;
    _description = Description ?? string.Empty;
  }

  private void Cancel() => MudDialog.Cancel();

  private void Save()
  {
    MudDialog.Close(DialogResult.Ok(new EditGroupDialogResult(
      _name.Trim(),
      string.IsNullOrWhiteSpace(_description) ? null : _description.Trim())));
  }
}

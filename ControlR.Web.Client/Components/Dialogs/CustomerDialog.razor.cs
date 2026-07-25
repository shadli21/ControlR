namespace ControlR.Web.Client.Components.Dialogs;

public sealed record CustomerDialogResult(string Name, string? Description, string? Notes);

public partial class CustomerDialog : ComponentBase
{
  private string _description = string.Empty;
  private string _name = string.Empty;
  private string _notes = string.Empty;

  [Parameter]
  public string? Description { get; set; }

  [CascadingParameter]
  public required IMudDialogInstance MudDialog { get; init; }

  [Parameter]
  public string? Name { get; set; }

  [Parameter]
  public string? Notes { get; set; }

  protected override void OnInitialized()
  {
    _name = Name ?? string.Empty;
    _description = Description ?? string.Empty;
    _notes = Notes ?? string.Empty;
  }

  private void Cancel() => MudDialog.Cancel();

  private void Save()
  {
    MudDialog.Close(DialogResult.Ok(new CustomerDialogResult(
      _name.Trim(),
      string.IsNullOrWhiteSpace(_description) ? null : _description.Trim(),
      string.IsNullOrWhiteSpace(_notes) ? null : _notes.Trim())));
  }
}

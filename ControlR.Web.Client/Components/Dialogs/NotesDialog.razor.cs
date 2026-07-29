namespace ControlR.Web.Client.Components.Dialogs;

public partial class NotesDialog : ComponentBase
{
  [CascadingParameter]
  public required IMudDialogInstance MudDialog { get; init; }

  [Parameter]
  public required string Notes { get; set; }

  private void Close() => MudDialog.Close();
}

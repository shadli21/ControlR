using ControlR.Libraries.Api.Contracts.Enums;

namespace ControlR.Web.Client.Components.Dialogs;

public partial class PermissionAssignmentPanelDialog : ComponentBase
{
  [CascadingParameter]
  public required IMudDialogInstance MudDialog { get; init; }

  [Parameter]
  public required Guid PrincipalId { get; set; }

  [Parameter]
  public required PermissionPrincipalKind PrincipalKind { get; set; }

  private void Close() => MudDialog.Close();
}

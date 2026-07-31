using InternalDtos = ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.Web.Client.Components.Shared;

public partial class PermissionAssignmentPanel : ComponentBase
{
  private readonly HashSet<Guid> _togglingIds = [];

  private InternalDtos.PermissionAssignmentDto[]? _assignments;
  private bool _loading;
  private PresetApplyMode _presetMode = PresetApplyMode.Merge;
  private InternalDtos.PermissionPresetDto[] _presets = [];
  private Guid? _presetScopeId;
  private PermissionScopeKind _presetScopeKind = PermissionScopeKind.Tenant;
  private PermissionPrincipalKind _principalKind = PermissionPrincipalKind.User;
  private IReadOnlyCollection<string> _selectedPresetNames = [];
  private Guid? _selectedPrincipalId;

  [Inject]
  public required IControlrApi ControlrApi { get; init; }

  [Inject]
  public required IDialogService DialogService { get; init; }

  [Parameter]
  public bool IsPrincipalLocked { get; set; }

  [Parameter]
  public Guid? PrincipalId { get; set; }

  [Parameter]
  public PermissionPrincipalKind? PrincipalKind { get; set; }

  [Inject]
  public required ISnackbar Snackbar { get; init; }

  protected override async Task OnAfterRenderAsync(bool firstRender)
  {
    if (firstRender)
    {
      var presetsResult = await ControlrApi.Internal.PermissionAssignments.GetPresets();
      if (presetsResult.IsSuccess)
      {
        _presets = presetsResult.Value;
      }

      if (IsPrincipalLocked && _selectedPrincipalId is not null)
      {
        await LoadAssignments();
      }
    }
  }

  protected override void OnParametersSet()
  {
    if (IsPrincipalLocked && PrincipalKind is { } kind && PrincipalId is { } id)
    {
      _principalKind = kind;
      _selectedPrincipalId = id;
    }
  }

  private async Task ApplyPresets()
  {
    if (_selectedPrincipalId is null || !_selectedPresetNames.Any())
    {
      return;
    }

    var permissionNames = _selectedPresetNames
      .SelectMany(name => _presets.FirstOrDefault(p => p.Name == name)?.Permissions ?? [])
      .Distinct()
      .ToList();

    if (permissionNames.Count == 0)
    {
      return;
    }

    if (_presetMode == PresetApplyMode.Replace)
    {
      var confirmed = await DialogService.ShowMessageBoxAsync(
        "Replace Assignments",
        $"This will replace all existing assignments with the selected preset permissions ({permissionNames.Count} permission(s)). Continue?",
        "Replace", "Cancel");

      if (!confirmed.GetValueOrDefault())
      {
        return;
      }

      await DeleteAllAssignments();
    }
    else
    {
      var existingNames = (_assignments ?? [])
        .Where(a => a.ScopeKind == _presetScopeKind && a.ScopeId == _presetScopeId)
        .Select(a => a.PermissionName)
        .ToHashSet(StringComparer.OrdinalIgnoreCase);

      permissionNames = permissionNames
        .Where(p => !existingNames.Contains(p))
        .ToList();

      if (permissionNames.Count == 0)
      {
        Snackbar.Add("All preset permissions already assigned", Severity.Info);
        return;
      }
    }

    foreach (var permissionName in permissionNames)
    {
      var request = new InternalDtos.CreatePermissionAssignmentRequestDto(
        _principalKind,
        _selectedPrincipalId.Value,
        permissionName,
        PermissionEffect.Allow,
        _presetScopeKind,
        _presetScopeId,
        null);

      var result = await ControlrApi.Internal.PermissionAssignments.Create(request);
      if (!result.IsSuccess)
      {
        Snackbar.Add($"Failed to assign {permissionName}: {result.Reason}", Severity.Error);
      }
    }

    Snackbar.Add($"Applied {permissionNames.Count} permission(s)", Severity.Success);
    await LoadAssignments();
  }

  private async Task CreateAssignment()
  {
    if (!TryGetSelectedPrincipal(out var kind, out var principalId))
    {
      return;
    }

    var parameters = new DialogParameters<PermissionAssignmentDialog>
    {
      { x => x.PrincipalKind, kind },
      { x => x.PrincipalId, principalId }
    };

    var dialogOptions = PermissionAssignmentDialog.DefaultOptions;

    var dialog = await DialogService.ShowAsync<PermissionAssignmentDialog>("Create Assignment", parameters, dialogOptions);
    var result = await dialog.Result;

    if (result is not null && !result.Canceled)
    {
      await LoadAssignments();
    }
  }

  private async Task DeleteAllAssignments()
  {
    if (_assignments is null)
    {
      return;
    }

    foreach (var assignment in _assignments)
    {
      var result = await ControlrApi.Internal.PermissionAssignments.Delete(assignment.Id);
      if (!result.IsSuccess)
      {
        Snackbar.Add($"Failed to delete {assignment.PermissionName}: {result.Reason}", Severity.Error);
      }
    }
  }

  private async Task DeleteAssignment(InternalDtos.PermissionAssignmentDto assignment)
  {
    var confirmed = await DialogService.ShowMessageBoxAsync(
      "Delete Assignment",
      $"Delete the \"{assignment.PermissionName}\" ({assignment.Effect}) assignment?",
      "Delete", "Cancel");

    if (!confirmed.GetValueOrDefault())
    {
      return;
    }

    var result = await ControlrApi.Internal.PermissionAssignments.Delete(assignment.Id);
    if (!result.IsSuccess)
    {
      Snackbar.Add(result.Reason, Severity.Error);
      return;
    }

    Snackbar.Add("Assignment deleted", Severity.Success);
    await LoadAssignments();
  }

  private async Task EditAssignment(InternalDtos.PermissionAssignmentDto assignment)
  {
    var parameters = new DialogParameters<PermissionAssignmentDialog>
    {
      { x => x.ExistingAssignment, assignment },
      { x => x.PrincipalId, assignment.PrincipalId },
      { x => x.PrincipalKind, assignment.PrincipalKind }
    };

    var dialogOptions = PermissionAssignmentDialog.DefaultOptions;

    var dialog = await DialogService.ShowAsync<PermissionAssignmentDialog>("Edit Assignment", parameters, dialogOptions);
    var result = await dialog.Result;

    if (result is not null && !result.Canceled)
    {
      await LoadAssignments();
    }
  }

  private async Task LoadAssignments()
  {
    if (_selectedPrincipalId is null)
    {
      return;
    }

    _loading = true;
    await InvokeAsync(StateHasChanged);

    try
    {
      var result = await ControlrApi.Internal.PermissionAssignments.GetByPrincipal(_principalKind.ToString(), _selectedPrincipalId.Value);
      if (result.IsSuccess)
      {
        _assignments = result.Value;
      }
      else
      {
        Snackbar.Add(result.Reason, Severity.Error);
      }
    }
    finally
    {
      _loading = false;
      await InvokeAsync(StateHasChanged);
    }
  }

  private async Task OnPresetSelectionChanged(IReadOnlyCollection<string> values)
  {
    _selectedPresetNames = values;
    await InvokeAsync(StateHasChanged);
  }

  private async Task OnPrincipalIdChanged(Guid? id)
  {
    _selectedPrincipalId = id;
    _assignments = null;

    if (id is not null)
    {
      await LoadAssignments();
    }
  }

  private async Task OnPrincipalKindChanged(PermissionPrincipalKind kind)
  {
    _principalKind = kind;
    _selectedPrincipalId = null;
    _assignments = null;
    await InvokeAsync(StateHasChanged);

    if (_selectedPrincipalId is not null)
    {
      await LoadAssignments();
    }
  }

  private async Task ShowNotes(string? notes)
  {
    if (string.IsNullOrWhiteSpace(notes))
    {
      return;
    }

    var dialogOptions = new DialogOptions
    {
      MaxWidth = MaxWidth.Medium,
      FullWidth = true
    };

    var parameters = new DialogParameters<NotesDialog>
    {
      { x => x.Notes, notes }
    };

    await DialogService.ShowAsync<NotesDialog>("Notes", parameters, dialogOptions);
  }

  private async Task ToggleEnabled(InternalDtos.PermissionAssignmentDto assignment, bool enabled)
  {
    if (_togglingIds.Contains(assignment.Id))
    {
      return;
    }

    _togglingIds.Add(assignment.Id);

    try
    {
      var updateRequest = new InternalDtos.UpdatePermissionAssignmentRequestDto(
        assignment.PermissionName,
        assignment.Effect,
        assignment.ScopeKind,
        assignment.ScopeId,
        assignment.Notes,
        enabled);

      var result = await ControlrApi.Internal.PermissionAssignments.Update(assignment.Id, updateRequest);
      if (!result.IsSuccess)
      {
        Snackbar.Add(result.Reason, Severity.Error);
        return;
      }

      if (_assignments is not null)
      {
        var index = Array.IndexOf(_assignments, assignment);
        if (index >= 0)
        {
          var updated = _assignments[index] with { IsEnabled = enabled };
          _assignments = [.. _assignments[..index], updated, .. _assignments[(index + 1)..]];
        }
      }
    }
    finally
    {
      _togglingIds.Remove(assignment.Id);
    }
  }

  private bool TryGetSelectedPrincipal(out PermissionPrincipalKind kind, out Guid principalId)
  {
    if (_selectedPrincipalId is null)
    {
      Snackbar.Add("Select a principal first", Severity.Error);
      kind = default;
      principalId = default;
      return false;
    }

    kind = _principalKind;
    principalId = _selectedPrincipalId.Value;
    return true;
  }

  private enum PresetApplyMode
  {
    Merge,
    Replace
  }
}

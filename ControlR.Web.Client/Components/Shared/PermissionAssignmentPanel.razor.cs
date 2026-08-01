using ControlR.Libraries.Api.Contracts.Dtos;
using Microsoft.AspNetCore.Components.Authorization;
using InternalDtos = ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.Web.Client.Components.Shared;

public partial class PermissionAssignmentPanel : ComponentBase
{
  private readonly HashSet<Guid> _togglingIds = [];

  private InternalDtos.PermissionAssignmentDto[]? _assignments;
  private bool _bulkDeleting;
  private Guid? _currentUserId;
  private bool _loading;
  private PresetApplyMode _presetMode = PresetApplyMode.Merge;
  private InternalDtos.PermissionPresetDto[] _presets = [];
  private PermissionPrincipalKind _principalKind = PermissionPrincipalKind.User;
  private string _searchString = string.Empty;
  private HashSet<InternalDtos.PermissionAssignmentDto> _selectedAssignments = [];
  private IReadOnlyCollection<string> _selectedPresetNames = [];
  private Guid? _selectedPrincipalId;

  [Inject]
  public required AuthenticationStateProvider AuthState { get; init; }

  [Inject]
  public required IControlrApi ControlrApi { get; init; }

  [Inject]
  public required IDialogService DialogService { get; init; }

  [Parameter]
  public bool IsPrincipalLocked { get; set; }

  [Inject]
  public required IPermissionCatalogStore PermissionCatalogStore { get; init; }

  [Parameter]
  public Guid? PrincipalId { get; set; }

  [Parameter]
  public PermissionPrincipalKind? PrincipalKind { get; set; }

  [Inject]
  public required ISnackbar Snackbar { get; init; }

  private Func<InternalDtos.PermissionAssignmentDto, bool> QuickFilter => assignment =>
  {
    if (string.IsNullOrWhiteSpace(_searchString))
    {
      return true;
    }

    return assignment.PermissionName.Contains(_searchString, StringComparison.OrdinalIgnoreCase) ||
           assignment.Effect.ToString().Contains(_searchString, StringComparison.OrdinalIgnoreCase) ||
           assignment.ScopeKind.ToString().Contains(_searchString, StringComparison.OrdinalIgnoreCase);
  };

  protected override async Task OnAfterRenderAsync(bool firstRender)
  {
    if (firstRender)
    {
      var state = await AuthState.GetAuthenticationStateAsync();
      if (state.User.TryGetUserId(out var currentUserId))
      {
        _currentUserId = currentUserId;
      }

      if (PermissionCatalogStore.Items.Count == 0)
      {
        await PermissionCatalogStore.Refresh();
      }

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

  private static int Breadth(PermissionScopeKind scopeKind) => scopeKind switch
  {
    PermissionScopeKind.Device => 0,
    PermissionScopeKind.DeviceGroup => 1,
    PermissionScopeKind.UserGroup => 1,
    PermissionScopeKind.CustomerTenant => 2,
    PermissionScopeKind.Tenant => 3,
    PermissionScopeKind.Server => 4,
    _ => 0
  };

  private async Task ApplyPresets()
  {
    if (_selectedPrincipalId is null || !_selectedPresetNames.Any())
    {
      return;
    }

    if (PermissionCatalogStore.Items.Count == 0)
    {
      await PermissionCatalogStore.Refresh();
    }

    var permissionNames = _selectedPresetNames
      .SelectMany(name => _presets.FirstOrDefault(p => p.Name == name)?.Permissions ?? [])
      .Distinct()
      .ToList();

    if (permissionNames.Count == 0)
    {
      return;
    }

    var assignmentRequests = permissionNames
      .Select(name => new InternalDtos.CreatePermissionAssignmentRequestDto(
        _principalKind,
        _selectedPrincipalId.Value,
        name,
        PermissionEffect.Allow,
        BroadestLegalScope(name),
        null,
        null))
      .ToArray();

    ApiResult result;
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

      result = await ControlrApi.Internal.PermissionAssignments.Replace(
        new InternalDtos.ReplacePermissionAssignmentsRequestDto(
          _principalKind, _selectedPrincipalId.Value, assignmentRequests));
    }
    else
    {
      var existingKeyed = (_assignments ?? [])
        .Select(a => (a.PermissionName, a.ScopeKind))
        .ToHashSet();

      assignmentRequests = [.. assignmentRequests
        .Where(r => !existingKeyed.Contains((r.PermissionName, r.ScopeKind)))];

      if (assignmentRequests.Length == 0)
      {
        Snackbar.Add("All preset permissions already assigned", Severity.Info);
        return;
      }

      result = await ControlrApi.Internal.PermissionAssignments.CreateMany(
        new InternalDtos.CreateManyPermissionAssignmentsRequestDto(assignmentRequests));
    }

    if (!result.IsSuccess)
    {
      Snackbar.Add(result.Reason, Severity.Error);
      return;
    }

    Snackbar.Add($"Applied {assignmentRequests.Length} permission(s)", Severity.Success);
    await LoadAssignments();
  }

  private PermissionScopeKind BroadestLegalScope(string permissionName)
  {
    var entry = PermissionCatalogStore.Items.FirstOrDefault(p => p.Name == permissionName);
    if (entry?.AllowedScopeKinds is { Length: > 0 } kinds)
    {
      return kinds.MaxBy(Breadth);
    }

    return PermissionScopeKind.Tenant;
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

  private async Task DeleteSelectedAssignments()
  {
    if (_selectedAssignments.Count == 0 || _bulkDeleting)
    {
      return;
    }

    var selected = _selectedAssignments.ToList();

    var confirmed = await DialogService.ShowMessageBoxAsync(
      "Delete Assignments",
      $"Delete {selected.Count} assignment(s)?",
      "Delete", "Cancel");

    if (!confirmed.GetValueOrDefault())
    {
      return;
    }

    _bulkDeleting = true;

    try
    {
      var result = await ControlrApi.Internal.PermissionAssignments.DeleteMany(
        new InternalDtos.DeleteManyPermissionAssignmentsRequestDto(
          [.. selected.Select(x => x.Id)]));

      if (!result.IsSuccess)
      {
        Snackbar.Add(result.Reason, Severity.Error);
        return;
      }

      _selectedAssignments.Clear();

      var successCount = result.Value.SuccessIds.Count;
      var failureCount = result.Value.FailureIds.Count;
      if (failureCount == 0)
      {
        Snackbar.Add($"Deleted {successCount} assignment(s)", Severity.Success);
      }
      else
      {
        Snackbar.Add($"Deleted {successCount} assignment(s); {failureCount} failed", Severity.Warning);
      }

      await LoadAssignments();
    }
    finally
    {
      _bulkDeleting = false;
    }
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

  /// <summary>
  /// True when the row is the current user's own last enabled Allow grant of a
  /// non-self-removable permission, so removing or disabling it would lock them out. Mirrors
  /// the server-side guard; the server remains authoritative.
  /// </summary>
  private bool IsProtectedSelfLastGrant(InternalDtos.PermissionAssignmentDto assignment)
  {
    if (_principalKind != PermissionPrincipalKind.User || _selectedPrincipalId != _currentUserId)
    {
      return false;
    }

    if (assignment.Effect != PermissionEffect.Allow || !assignment.IsEnabled)
    {
      return false;
    }

    var entry = PermissionCatalogStore.Items.FirstOrDefault(p => p.Name == assignment.PermissionName);
    if (entry is null || entry.SelfRemovable)
    {
      return false;
    }

    var grantCount = (_assignments ?? [])
      .Count(a => a.PermissionName == assignment.PermissionName &&
                  a.Effect == PermissionEffect.Allow &&
                  a.IsEnabled);

    return grantCount <= 1;
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
    _selectedAssignments.Clear();

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
    _selectedAssignments.Clear();
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

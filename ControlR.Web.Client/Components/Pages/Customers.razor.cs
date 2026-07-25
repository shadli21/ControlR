using ControlR.Web.Client.Authz;
using ControlR.Web.Client.Services;
using Microsoft.AspNetCore.Components;
using InternalDtos = ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.Web.Client.Components.Pages;

public partial class Customers : ComponentBase
{
  private IEnumerable<InternalDtos.CustomerDto> _customers = [];
  private bool _loading;
  private string _searchString = string.Empty;

  [Inject]
  public required IClipboardManager ClipboardManager { get; init; }

  [Inject]
  public required IControlrApi ControlrApi { get; init; }

  [Inject]
  public required IDialogService DialogService { get; init; }

  [Inject]
  public required ISnackbar Snackbar { get; init; }

  private Func<InternalDtos.CustomerDto, bool> QuickFilter => customer =>
  {
    if (string.IsNullOrWhiteSpace(_searchString))
    {
      return true;
    }

    return customer.Name.Contains(_searchString, StringComparison.OrdinalIgnoreCase) ||
           (customer.Description?.Contains(_searchString, StringComparison.OrdinalIgnoreCase) ?? false) ||
           (customer.Notes?.Contains(_searchString, StringComparison.OrdinalIgnoreCase) ?? false);
  };

  protected override async Task OnInitializedAsync()
  {
    await Refresh();
  }

  private async Task AssignDevices(InternalDtos.CustomerDto customer)
  {
    var parameters = new DialogParameters<AssignCustomerDevicesDialog>
    {
      { x => x.CustomerId, customer.Id }
    };

    var options = new DialogOptions
    {
      FullWidth = true,
      MaxWidth = MaxWidth.Medium
    };

    var dialog = await DialogService.ShowAsync<AssignCustomerDevicesDialog>($"Assign Devices to {customer.Name}", parameters, options);
    var result = await dialog.Result;

    if (result is not null && !result.Canceled)
    {
      await Refresh();
    }
  }

  private async Task CopyId(Guid id)
  {
    await ClipboardManager.SetText(id.ToString());
    Snackbar.Add("Copied to clipboard", Severity.Success);
  }

  private async Task CreateCustomer()
  {
    var dialog = await DialogService.ShowAsync<CustomerDialog>("Create Customer");
    var result = await dialog.Result;

    if (result is null || result.Canceled || result.Data is not CustomerDialogResult dialogResult)
    {
      return;
    }

    var createResult = await ControlrApi.Internal.Customers.Create(
      new InternalDtos.CreateCustomerRequestDto(dialogResult.Name, dialogResult.Description, dialogResult.Notes));

    if (!createResult.IsSuccess)
    {
      Snackbar.Add(createResult.Reason, Severity.Error);
      return;
    }

    Snackbar.Add("Customer created", Severity.Success);
    await Refresh();
  }

  private async Task DeleteCustomer(InternalDtos.CustomerDto customer)
  {
    var confirmed = await DialogService.ShowMessageBoxAsync(
      "Delete Customer",
      $"Are you sure you want to delete \"{customer.Name}\"? Devices assigned to this customer will become unassigned.",
      "Delete", "Cancel");

    if (!confirmed.GetValueOrDefault())
    {
      return;
    }

    var result = await ControlrApi.Internal.Customers.Delete(customer.Id);
    if (!result.IsSuccess)
    {
      Snackbar.Add(result.Reason, Severity.Error);
      return;
    }

    Snackbar.Add("Customer deleted", Severity.Success);
    await Refresh();
  }

  private async Task EditCustomer(InternalDtos.CustomerDto customer)
  {
    var parameters = new DialogParameters<CustomerDialog>
    {
      { x => x.Name, customer.Name },
      { x => x.Description, customer.Description },
      { x => x.Notes, customer.Notes }
    };

    var dialog = await DialogService.ShowAsync<CustomerDialog>("Edit Customer", parameters);
    var result = await dialog.Result;

    if (result is null || result.Canceled || result.Data is not CustomerDialogResult dialogResult)
    {
      return;
    }

    var updateResult = await ControlrApi.Internal.Customers.Update(
      customer.Id,
      new InternalDtos.UpdateCustomerRequestDto(dialogResult.Name, dialogResult.Description, dialogResult.Notes));

    if (!updateResult.IsSuccess)
    {
      Snackbar.Add(updateResult.Reason, Severity.Error);
      return;
    }

    Snackbar.Add("Customer updated", Severity.Success);
    await Refresh();
  }

  private async Task Refresh()
  {
    _loading = true;
    StateHasChanged();

    try
    {
      var result = await ControlrApi.Internal.Customers.GetAll();
      if (result.IsSuccess)
      {
        _customers = result.Value;
      }
      else
      {
        Snackbar.Add(result.Reason, Severity.Error);
      }
    }
    finally
    {
      _loading = false;
      StateHasChanged();
    }
  }

  private string TruncateId(Guid id)
  {
    return $"{id.ToString()[..8]}...";
  }
}

namespace ControlR.Web.Client.Components.Shared;

public partial class ExpirationPicker : ComponentBase
{
  private const int CustomValue = -1;
  private const int NeverValue = 0;

  private int _choice = NeverValue;
  private DateTime? _customDate;
  private TimeSpan? _customTime;
  private bool _isInitialized;

  [Inject]
  public required TimeProvider TimeProvider { get; init; }

  [Parameter]
  public DateTimeOffset? Value { get; set; }

  [Parameter]
  public EventCallback<DateTimeOffset?> ValueChanged { get; set; }

  private DateTime MinDate => TimeProvider.GetLocalNow().Date;

  protected override void OnParametersSet()
  {
    base.OnParametersSet();

    if (_isInitialized)
    {
      return;
    }

    _isInitialized = true;

    if (Value is null)
    {
      _choice = NeverValue;
      return;
    }

    // Reflect a pre-seeded expiration in the dropdown. Match the closest preset
    // (30/90/365 days) for the common case; otherwise fall back to the custom picker.
    var expiresIn = Value.Value - TimeProvider.GetUtcNow();
    var presetDays = new int[] { 30, 90, 365 }
      .FirstOrDefault(d => (expiresIn - TimeSpan.FromDays(d)).Duration() <= TimeSpan.FromDays(1));
    if (presetDays != 0)
    {
      _choice = presetDays;
      return;
    }

    _choice = CustomValue;
    var local = Value.Value.ToLocalTime();
    _customDate = local.Date;
    _customTime = local.TimeOfDay;
  }

  private DateTimeOffset BuildCustomValue()
  {
    var date = _customDate ?? TimeProvider.GetLocalNow().Date;
    var local = date.Date + (_customTime ?? TimeSpan.Zero);
    var offset = TimeProvider.LocalTimeZone.GetUtcOffset(local);
    return new DateTimeOffset(local, offset);
  }

  private async Task OnChoiceChanged(int choice)
  {
    _choice = choice;

    switch (choice)
    {
      case NeverValue:
        await ValueChanged.InvokeAsync(null);
        break;
      case CustomValue:
        _customDate ??= TimeProvider.GetLocalNow().Date;
        _customTime ??= TimeProvider.GetLocalNow().TimeOfDay;
        await ValueChanged.InvokeAsync(BuildCustomValue());
        break;
      default:
        await ValueChanged.InvokeAsync(TimeProvider.GetUtcNow().AddDays(choice));
        break;
    }
  }

  private async Task OnDateChanged(DateTime? date)
  {
    _customDate = date;
    if (_customDate is not null)
    {
      await ValueChanged.InvokeAsync(BuildCustomValue());
    }
  }

  private async Task OnTimeChanged(TimeSpan? time)
  {
    _customTime = time;
    if (_customDate is not null)
    {
      await ValueChanged.InvokeAsync(BuildCustomValue());
    }
  }
}

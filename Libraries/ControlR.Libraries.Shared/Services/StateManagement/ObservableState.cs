using System.Collections.Concurrent;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using ControlR.Libraries.Shared.Collections;

namespace ControlR.Libraries.Shared.Services.StateManagement;

public interface IStateBase
{
  Task NotifyStateChanged();
  IDisposable OnStateChanged(Func<Task> callback);
}
public abstract class ObservableState(ILogger<ObservableState> logger) : IStateBase, INotifyPropertyChanged
{
  private readonly ConcurrentList<Func<Task>> _changeHandlers = [];
  private readonly ConcurrentDictionary<string, object?> _propertyValues = [];

  public event PropertyChangedEventHandler? PropertyChanged;

  protected ILogger<ObservableState> Logger { get; } = logger;

  public virtual Task NotifyStateChanged()
  {
    return InvokeChangeHandlers();
  }

  public virtual IDisposable OnStateChanged(Func<Task> callback)
  {
    _changeHandlers.Add(callback);
    return new CallbackDisposable(() =>
    {
      _changeHandlers.Remove(callback);
    });
  }

  protected T? Get<T>(T? defaultValue = default, [CallerMemberName] string propertyName = "")
  {
    if (_propertyValues.TryGetValue(propertyName, out var value) &&
        value is T typedValue)
    {
      return typedValue;
    }

    return defaultValue;
  }

  protected void Set<T>(T? value, [CallerMemberName] string propertyName = "")
  {
    _propertyValues[propertyName] = value;
    PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    _ = NotifyStateChanged();
  }

  private async Task InvokeChangeHandlers()
  {
    foreach (var handler in _changeHandlers)
    {
      try
      {
        await handler();
      }
      catch (Exception ex)
      {
        Logger.LogError(ex, "Error occurred while invoking change handler.");
      }
    }
  }
}
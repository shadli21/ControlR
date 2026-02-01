namespace ControlR.DesktopClient.Linux.Services;

/// <summary>
/// Utility class for parsing tuple values from Wayland portal properties.
/// </summary>
internal static class WaylandTupleParser
{
  /// <summary>
  /// Attempts to convert a value to an integer from various numeric types.
  /// </summary>
  public static bool TryConvertToInt(object? value, out int result)
  {
    result = 0;

    switch (value)
    {
      case int i:
        result = i;
        return true;
      case long l:
        result = (int)l;
        return true;
      case uint u:
        result = (int)u;
        return true;
      case double d:
        result = (int)d;
        return true;
      default:
        return false;
    }
  }

  /// <summary>
  /// Attempts to parse a tuple of two integers from various tuple-like types.
  /// Supports ValueTuple, arrays, and IList types.
  /// </summary>
  public static bool TryParseTuple2(object? value, out int x, out int y)
  {
    x = 0;
    y = 0;

    switch (value)
    {
      case ValueTuple<int, int> tuple:
        x = tuple.Item1;
        y = tuple.Item2;
        return true;
      case ValueTuple<long, long> longTuple:
        x = (int)longTuple.Item1;
        y = (int)longTuple.Item2;
        return true;
      case object[] { Length: >= 2 } arr when TryConvertToInt(arr[0], out var ax) && TryConvertToInt(arr[1], out var ay):
        x = ax;
        y = ay;
        return true;
      case System.Collections.IList list when list.Count >= 2 && TryConvertToInt(list[0], out var lx) && TryConvertToInt(list[1], out var ly):
        x = lx;
        y = ly;
        return true;
      default:
        return false;
    }
  }
}

namespace ControlR.Libraries.Shared.Comparers;

/// <summary>
/// Compares objects by reference (not by value) for use in generic collections.
/// </summary>
public sealed class ReferenceEqualityComparer<T> : IEqualityComparer<T>
  where T : class
{
  public static readonly ReferenceEqualityComparer<T> Instance = new();

  public bool Equals(T? x, T? y) => ReferenceEquals(x, y);
  public int GetHashCode(T? obj) => System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(obj);
}

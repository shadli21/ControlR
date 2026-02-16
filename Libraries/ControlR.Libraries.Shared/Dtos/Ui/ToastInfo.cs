using ControlR.Libraries.Shared.Enums;
namespace ControlR.Libraries.Shared.Dtos.Ui;

[MessagePackObject]
public record ToastInfo(
  [property: Key(0)] string Message,
  [property: Key(1)] MessageSeverity MessageSeverity);

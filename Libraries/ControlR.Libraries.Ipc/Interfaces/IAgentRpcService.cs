using ControlR.Libraries.Shared.Dtos.IpcDtos;
using PolyType;
using StreamJsonRpc;

namespace ControlR.Libraries.Ipc.Interfaces;

[JsonRpcContract]
[GenerateShape(IncludeMethods = MethodShapeFlags.PublicInstance)]
public partial interface IAgentRpcService
{
    Task<bool> SendChatResponse(ChatResponseIpcDto dto);
}

using System.Threading.Channels;

namespace ControlR.Web.Server.Services.Authorization;

/// <summary>
/// Singleton queue for credential scope trim commands. Backed by an unbounded
/// <see cref="Channel{T}"/> so the auth handler never blocks on enqueue.
/// </summary>
public interface IPatScopeTrimQueue
{
  ChannelReader<PatScopeTrimCommand> Reader { get; }

  void Enqueue(PatScopeTrimCommand command);
}

public class PatScopeTrimQueue : IPatScopeTrimQueue
{
  private readonly Channel<PatScopeTrimCommand> _channel =
    Channel.CreateUnbounded<PatScopeTrimCommand>(new UnboundedChannelOptions
    {
      SingleReader = true
    });

  public ChannelReader<PatScopeTrimCommand> Reader => _channel.Reader;

  public void Enqueue(PatScopeTrimCommand command)
  {
    _channel.Writer.TryWrite(command);
  }
}

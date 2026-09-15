using System.Text;
using KalitkaAgent;
using Xunit;

namespace KalitkaAgent.Windows.Tests;

/// <summary>
/// The pipe request read is bounded: it stops at a newline or a byte cap, so a client that connects
/// and streams without ever terminating the line cannot make the agent read forever. (The per-
/// connection timeout, instance pool and ACL are the rest of the DoS fix; this is the length bound.)
/// </summary>
public class PipeReadTests
{
    private static async Task<object?> Read(byte[] input, int maxBytes = 8192) =>
        await Worker.ReadRequestObjectAsync(new MemoryStream(input), maxBytes, default);

    [Fact]
    public async Task A_normal_request_line_parses()
    {
        Assert.NotNull(await Read(Encoding.UTF8.GetBytes("{\"action\":\"rdp\"}\n")));
    }

    [Fact]
    public async Task A_newline_is_optional_within_the_limit()
    {
        Assert.NotNull(await Read(Encoding.UTF8.GetBytes("{\"action\":\"rdp\"}")));
    }

    [Fact]
    public async Task An_empty_stream_is_rejected()
    {
        Assert.Null(await Read(Array.Empty<byte>()));
    }

    [Fact]
    public async Task An_over_long_line_without_a_newline_is_rejected()
    {
        // A client streaming past the cap with no newline: bounded and refused, not read forever.
        var flood = Encoding.UTF8.GetBytes(new string('a', 100));
        Assert.Null(await Read(flood, maxBytes: 16));
    }

    [Fact]
    public async Task Non_json_is_rejected()
    {
        Assert.Null(await Read(Encoding.UTF8.GetBytes("not json at all\n")));
    }
}

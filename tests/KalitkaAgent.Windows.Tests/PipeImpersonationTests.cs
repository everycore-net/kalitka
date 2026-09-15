using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;
using KalitkaAgent;
using Xunit;

namespace KalitkaAgent.Windows.Tests;

/// <summary>
/// The pipe exchange over a REAL named pipe, where client-token impersonation actually happens — which
/// the <see cref="PipeReadTests"/> MemoryStream reads cannot exercise: <c>RunAsClient</c> does not apply
/// to a MemoryStream, so subject resolution was dead behind 50 green tests and a live stand raised no
/// requests at all. These pin the ordering invariant behind that outage: the server must read from the
/// pipe before Windows will let it impersonate the caller.
/// </summary>
[SupportedOSPlatform("windows")]
public class PipeImpersonationTests
{
    private static async Task<(NamedPipeServerStream server, NamedPipeClientStream client)> ConnectedPairAsync()
    {
        var name = "kalitka-test-" + Guid.NewGuid().ToString("N");
        var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        var accept = server.WaitForConnectionAsync();
        await client.ConnectAsync(2000);
        await accept;
        return (server, client);
    }

    [Fact]
    public async Task Reading_first_lets_the_caller_sid_be_resolved()
    {
        var (server, client) = await ConnectedPairAsync();
        using (server)
        using (client)
        {
            await client.WriteAsync(Encoding.UTF8.GetBytes("{\"action\":\"rdp\"}\n"));
            await client.FlushAsync();

            // Production order: read the request first, THEN impersonate to resolve who sent it.
            var req = await Worker.ReadRequestObjectAsync(server, 8192, default);
            Assert.NotNull(req);

            var caller = SubjectResolver.Resolve(server);
            using var me = WindowsIdentity.GetCurrent();
            Assert.Equal(me.User!.Value, caller.Sid);        // the OS-asserted SID from the client token
            Assert.StartsWith("os:", caller.SubjectIdentity); // the label Core matches, never caller-typed
        }
    }

    [Fact]
    public async Task Impersonating_before_any_read_throws_which_is_why_the_order_matters()
    {
        var (server, client) = await ConnectedPairAsync();
        using (server)
        using (client)
        {
            await client.WriteAsync(Encoding.UTF8.GetBytes("{\"action\":\"rdp\"}\n"));
            await client.FlushAsync();

            // No server-side read yet: Windows refuses impersonation. This is the exact failure that
            // dropped every request as 401 while the service still reported RUNNING.
            Assert.ThrowsAny<IOException>(() => SubjectResolver.Resolve(server));
        }
    }
}

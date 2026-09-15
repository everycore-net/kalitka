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
///
/// Every wait here is bounded, and the synchronous <see cref="SubjectResolver.Resolve"/> is run off the
/// test thread and raced against a budget — because a broken invariant must turn the test RED in
/// seconds, never hang the job. (An earlier version with no timeouts ran a Windows CI runner for hours:
/// on some platforms <c>RunAsClient</c> before a read <i>blocks</i> instead of throwing.)
/// </summary>
[SupportedOSPlatform("windows")]
public class PipeImpersonationTests
{
    private static readonly TimeSpan Budget = TimeSpan.FromSeconds(5);

    private static async Task<(NamedPipeServerStream server, NamedPipeClientStream client)> ConnectedPairAsync(CancellationToken ct)
    {
        var name = "kalitka-test-" + Guid.NewGuid().ToString("N");
        // A real buffer (not the 0-byte default of the short overload): otherwise the client's write
        // blocks until the server reads, and the "resolve before read" test — which deliberately never
        // reads — would deadlock the write instead of exercising impersonation.
        var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous, inBufferSize: 4096, outBufferSize: 4096);
        var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        var accept = server.WaitForConnectionAsync(ct);
        await client.ConnectAsync(ct);
        await accept;
        return (server, client);
    }

    /// <summary>Run the (synchronous, uncancellable) resolve off-thread and bound it: completed+result on
    /// success, completed+error if it threw, or not-completed if it blocked past the budget. A blocked
    /// call is left to fault when the pipe is disposed; its exception is observed so it never surfaces as
    /// an unobserved-task exception.</summary>
    private static async Task<(bool completed, CallerSubject? result, Exception? error)> TryResolveAsync(NamedPipeServerStream pipe)
    {
        var task = Task.Run(() => SubjectResolver.Resolve(pipe));
        if (await Task.WhenAny(task, Task.Delay(Budget)) != task)
        {
            _ = task.ContinueWith(t => { _ = t.Exception; }, TaskScheduler.Default);
            return (false, null, null);
        }
        return task.IsFaulted ? (true, null, task.Exception!.GetBaseException()) : (true, task.Result, null);
    }

    [Fact(Timeout = 30000)]
    public async Task Reading_first_lets_the_caller_sid_be_resolved()
    {
        using var cts = new CancellationTokenSource(Budget);
        var (server, client) = await ConnectedPairAsync(cts.Token);
        using (server)
        using (client)
        {
            await client.WriteAsync(Encoding.UTF8.GetBytes("{\"action\":\"rdp\"}\n"), cts.Token);
            await client.FlushAsync(cts.Token);

            // Production order: read the request first, THEN impersonate to resolve who sent it.
            var req = await Worker.ReadRequestObjectAsync(server, 8192, cts.Token);
            Assert.NotNull(req);

            var (completed, caller, error) = await TryResolveAsync(server);
            Assert.True(completed, "Resolve did not complete after a read — impersonation stalled on this runner");
            Assert.Null(error);
            using var me = WindowsIdentity.GetCurrent();
            Assert.Equal(me.User!.Value, caller!.Sid);        // the OS-asserted SID from the client token
            Assert.StartsWith("os:", caller.SubjectIdentity); // the label Core matches, never caller-typed
        }
    }

    [Fact(Timeout = 30000)]
    public async Task Impersonating_before_any_read_never_returns_a_subject()
    {
        using var cts = new CancellationTokenSource(Budget);
        var (server, client) = await ConnectedPairAsync(cts.Token);
        using (server)
        using (client)
        {
            await client.WriteAsync(Encoding.UTF8.GetBytes("{\"action\":\"rdp\"}\n"), cts.Token);
            await client.FlushAsync(cts.Token);

            // No server-side read yet. The invariant: impersonation must not hand back a caller identity
            // before a read. Where the outage was seen RunAsClient throws; on another platform/token it
            // may block instead — both uphold the invariant. Only a clean CallerSubject coming back would
            // mean it was broken (the very silent-success we must never allow).
            var (_, caller, _) = await TryResolveAsync(server);
            Assert.Null(caller);
        }
    }
}

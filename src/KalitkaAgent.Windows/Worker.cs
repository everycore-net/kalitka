using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace KalitkaAgent;

/// <summary>
/// The service loop. It owns one local named pipe that authenticated local processes connect
/// to; for each connection it reads the caller's Windows identity off the pipe token (the
/// asserted subject), reads the requested resource from the caller, raises a signed request to
/// Core, and returns Core's verdict. The caller chooses <i>what</i> (resource/command); the OS
/// decides <i>who</i> (subject/user) — the caller cannot name someone else.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class Worker : BackgroundService
{
    private readonly AgentConfig _cfg;
    private readonly CoreClient _core;
    private readonly RdpEnforcer _rdp;
    private readonly RdpActivator _activator;
    private readonly AgentIdentity _identity;
    private readonly ILogger<Worker> _log;
    private string _agentId = "";

    public Worker(IOptions<AgentConfig> cfg, CoreClient core, RdpEnforcer rdp, RdpActivator activator,
        AgentIdentity identity, ILogger<Worker> log)
    {
        _cfg = cfg.Value;
        _core = core;
        _rdp = rdp;
        _activator = activator;
        _identity = identity;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _agentId = await EnsureEnrolledAsync(stoppingToken);
        if (!string.IsNullOrEmpty(_agentId))
            _identity.Set(_agentId);   // hand the id to the log watcher and to reconcile's Core check

        // Crash recovery before we accept new work: re-assert leases Core still confirms, close the
        // ones it no longer does, and honour local expiry when Core cannot be reached. Runs after
        // enrolment so the Core second source is available; if unenrolled it falls back to local expiry.
        try { await _rdp.ReconcileAsync(stoppingToken); }
        catch (Exception ex) { _log.LogError(ex, "RDP reconcile at startup failed"); }

        if (string.IsNullOrEmpty(_agentId))
        {
            _log.LogError("Not enrolled and no enrollment token configured; idle. "
                + "Set Kalitka:EnrollmentToken to a one-time token from a Core admin and restart.");
            return;
        }
        _log.LogInformation("Enrolled as agent {AgentId}; listening on pipe \\\\.\\pipe\\{Pipe} ({Instances} instances)",
            _agentId, _cfg.PipeName, _cfg.PipeInstances);

        // Several instances serve in parallel, so one stalled client (dropped after the per-connection
        // timeout) never blocks the rest.
        var loops = Enumerable.Range(0, Math.Max(1, _cfg.PipeInstances)).Select(_ => AcceptLoop(stoppingToken));
        await Task.WhenAll(loops);
    }

    private async Task AcceptLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { await ServeOneAsync(ct); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex) { _log.LogError(ex, "pipe connection failed"); }
        }
    }

    private async Task ServeOneAsync(CancellationToken ct)
    {
        using var pipe = CreatePipe(_cfg.PipeName, Math.Max(1, _cfg.PipeInstances));
        await pipe.WaitForConnectionAsync(ct);   // waits for a client indefinitely; not the DoS surface

        // Once a client is connected, bound the whole exchange: a client that connects and then sends
        // nothing (or dribbles) must not hold this instance open. On timeout the pipe is disposed.
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(Math.Max(1, _cfg.PipeConnectionTimeoutSeconds)));
        var cct = timeout.Token;
        try
        {
            CallerSubject caller;
            try { caller = SubjectResolver.Resolve(pipe); }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "could not resolve caller identity");
                await WriteAsync(pipe, new { status = 401, error = "identity-unresolved" }, cct);
                return;
            }

            var req = await ReadRequestAsync(pipe, _cfg.PipeMaxRequestBytes, cct);
            if (req is null)
            {
                await WriteAsync(pipe, new { status = 400, error = "bad-request" }, cct);
                return;
            }

            object reply = (req.Action ?? "request") switch
            {
                "rdp" => await RaiseRdp(caller, cct),
                "rdp_activate" => await ActivateRdp(caller, req.RequestId, cct),
                _ => await RaiseGeneric(caller, req, cct),
            };
            await WriteAsync(pipe, reply, cct);
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested && !ct.IsCancellationRequested)
        {
            _log.LogWarning("pipe client exceeded the {Seconds}s connection timeout; dropped", _cfg.PipeConnectionTimeoutSeconds);
        }
    }

    private async Task<object> RaiseGeneric(CallerSubject caller, PipeRequest req, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Resource)) return new { status = 400, error = "resource-required" };
        _log.LogInformation("Request from {Account} (sid {Sid}) for {Resource}", caller.Account, caller.Sid, req.Resource);
        var r = await _core.RaiseAsync(_agentId, caller, req.Resource, req.Command, ct);
        return new { status = r.Status, id = r.Id, state = r.State };
    }

    // RDP JIT: raise an rdp:<thishost> request for the pipe caller (subject asserted from the
    // token). The caller then polls with rdp_activate; on approval we redeem and add them to
    // Remote Desktop Users until the grant expires.
    private async Task<object> RaiseRdp(CallerSubject caller, CancellationToken ct)
    {
        var resource = "rdp:" + Environment.MachineName;
        _log.LogInformation("RDP request from {Account} (sid {Sid}) for {Resource}", caller.Account, caller.Sid, resource);
        var r = await _core.RaiseAsync(_agentId, caller, resource, command: null, ct);
        return new { status = r.Status, id = r.Id, state = r.State };
    }

    private async Task<object> ActivateRdp(CallerSubject caller, string? requestId, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(requestId)) return new { status = 400, error = "request-id-required" };
        var poll = await _core.PollAsync(_agentId, requestId, ct);
        if (poll.State != "approved" || string.IsNullOrEmpty(poll.Grant))
            return new { status = 200, granted = false, state = poll.State };

        // Redeem + beneficiary check + enable live in the shared activator, one implementation for
        // both the pipe path and the log watcher.
        var result = await _activator.RedeemAndGrantAsync(_agentId, caller, poll.Grant!, ct);
        if (result.Outcome == GrantOutcome.Granted)
            return new { status = 200, granted = true, expires_at = result.ExpiresAt!.Value.ToUnixTimeSeconds() };
        if (result.Outcome == GrantOutcome.Forbidden)
            return new { status = 403, granted = false, error = "beneficiary-mismatch" };
        return new { status = result.Status, granted = false, error = "redeem-failed" };
    }

    private async Task<string> EnsureEnrolledAsync(CancellationToken ct)
    {
        var state = AgentState.Load(_cfg.StatePath);
        if (!string.IsNullOrEmpty(state.AgentId)) return state.AgentId;
        if (string.IsNullOrEmpty(_cfg.EnrollmentToken)) return "";

        var id = await _core.EnrollAsync(_cfg.EnrollmentToken, Environment.MachineName, ct);
        new AgentState { AgentId = id }.Save(_cfg.StatePath);
        _log.LogInformation("Enrolled with Core; agent id {AgentId} persisted", id);
        return id;
    }

    // Local IPC only: grant connect/read/write to <b>interactive</b> logons on this machine (console
    // and RDP), and full control to SYSTEM. Interactive rather than AuthenticatedUsers deliberately —
    // the latter includes service and network logons, which have no business asking for a JIT grant.
    // The pipe never leaves the box.
    private static NamedPipeServerStream CreatePipe(string name, int maxInstances)
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),
            PipeAccessRights.ReadWrite, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));
        return NamedPipeServerStreamAcl.Create(
            name, PipeDirection.InOut, maxInstances, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous, 0, 0, security);
    }

    private sealed record PipeRequest(string? Action, string? Resource, string? Command, string? RequestId);

    /// <summary>Read one request line, bounded in length: read until a newline or
    /// <paramref name="maxBytes"/>, whichever comes first, and reject anything longer (a client that
    /// streams without ever terminating the line). Public and stream-based so it is unit-tested without
    /// a live pipe. Null = empty, too long, or not valid JSON.</summary>
    public static async Task<object?> ReadRequestObjectAsync(Stream stream, int maxBytes, CancellationToken ct) =>
        await ReadRequestAsync(stream, maxBytes, ct);

    private static async Task<PipeRequest?> ReadRequestAsync(Stream stream, int maxBytes, CancellationToken ct)
    {
        var buffer = new byte[maxBytes + 1];
        var total = 0;
        var nl = -1;
        while (total < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(total, buffer.Length - total), ct);
            if (n == 0) break;                                  // client closed
            var found = Array.IndexOf(buffer, (byte)'\n', total, n);
            total += n;
            if (found >= 0) { nl = found; break; }
        }

        var end = nl >= 0 ? nl : total;
        if (end == 0 || end > maxBytes) return null;            // empty, or too long with no newline
        var line = System.Text.Encoding.UTF8.GetString(buffer, 0, end).TrimEnd('\r');
        if (string.IsNullOrWhiteSpace(line)) return null;
        try { return JsonSerializer.Deserialize<PipeRequest>(line, JsonOpts); }
        catch (JsonException) { return null; }
    }

    private static async Task WriteAsync(NamedPipeServerStream pipe, object payload, CancellationToken ct)
    {
        var json = JsonSerializer.Serialize(payload, JsonOpts);
        await using var writer = new StreamWriter(pipe, System.Text.Encoding.UTF8, 1024, leaveOpen: true) { AutoFlush = true };
        await writer.WriteLineAsync(json.AsMemory(), ct);
    }

    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);
}

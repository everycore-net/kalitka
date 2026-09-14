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
    private readonly ILogger<Worker> _log;
    private string _agentId = "";

    public Worker(IOptions<AgentConfig> cfg, CoreClient core, RdpEnforcer rdp, ILogger<Worker> log)
    {
        _cfg = cfg.Value;
        _core = core;
        _rdp = rdp;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Crash recovery first: drop any RDP lease already expired while we were down, and
        // re-assert the ones still valid — before we accept new work.
        try { _rdp.Reconcile(); }
        catch (Exception ex) { _log.LogError(ex, "RDP reconcile at startup failed"); }

        _agentId = await EnsureEnrolledAsync(stoppingToken);
        if (string.IsNullOrEmpty(_agentId))
        {
            _log.LogError("Not enrolled and no enrollment token configured; idle. "
                + "Set Kalitka:EnrollmentToken to a one-time token from a Core admin and restart.");
            return;
        }
        _log.LogInformation("Enrolled as agent {AgentId}; listening on pipe \\\\.\\pipe\\{Pipe}", _agentId, _cfg.PipeName);

        while (!stoppingToken.IsCancellationRequested)
        {
            try { await ServeOneAsync(stoppingToken); }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) { _log.LogError(ex, "pipe connection failed"); }
        }
    }

    // One connection at a time is enough for the thin slice: approvals are human-paced.
    private async Task ServeOneAsync(CancellationToken ct)
    {
        using var pipe = CreatePipe(_cfg.PipeName);
        await pipe.WaitForConnectionAsync(ct);

        CallerSubject caller;
        try { caller = SubjectResolver.Resolve(pipe); }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "could not resolve caller identity");
            await WriteAsync(pipe, new { status = 401, error = "identity-unresolved" }, ct);
            return;
        }

        var req = await ReadRequestAsync(pipe, ct);
        if (req is null)
        {
            await WriteAsync(pipe, new { status = 400, error = "bad-request" }, ct);
            return;
        }

        object reply = (req.Action ?? "request") switch
        {
            "rdp" => await RaiseRdp(caller, ct),
            "rdp_activate" => await ActivateRdp(caller, req.RequestId, ct),
            _ => await RaiseGeneric(caller, req, ct),
        };
        await WriteAsync(pipe, reply, ct);
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

        var redeemed = await _core.RedeemAsync(_agentId, poll.Grant!, ct);
        if (redeemed.SessionId is null || redeemed.ExpiresAt is null)
            return new { status = redeemed.Status, granted = false, error = "redeem-failed" };

        // Belt and suspenders: only ever add RDP for the very person Core approved. The grant's
        // subject is the Core-approved account; it must be the caller activating now.
        if (!BeneficiaryMatches(redeemed.Subject, caller))
        {
            _log.LogWarning("RDP activate refused: grant subject {Subject} is not the caller {Account}", redeemed.Subject, caller.Account);
            return new { status = 403, granted = false, error = "beneficiary-mismatch" };
        }

        _rdp.Grant(new RdpLease(redeemed.SessionId, caller.Sid, caller.Account, redeemed.ExpiresAt.Value));
        return new { status = 200, granted = true, expires_at = redeemed.ExpiresAt.Value.ToUnixTimeSeconds() };
    }

    // The approved subject account tail (after the last '\' or ':') must equal the caller's user.
    private static bool BeneficiaryMatches(string? subject, CallerSubject caller)
    {
        if (string.IsNullOrEmpty(subject)) return false;
        var cut = Math.Max(subject.LastIndexOf('\\'), subject.LastIndexOf(':'));
        var tail = cut >= 0 && cut < subject.Length - 1 ? subject[(cut + 1)..] : subject;
        return string.Equals(tail, caller.User, StringComparison.OrdinalIgnoreCase);
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

    // Local IPC only: grant connect/read/write to authenticated users on this machine, and
    // full control to SYSTEM/Administrators. The pipe never leaves the box.
    private static NamedPipeServerStream CreatePipe(string name)
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
            PipeAccessRights.ReadWrite, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));
        return NamedPipeServerStreamAcl.Create(
            name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous, 0, 0, security);
    }

    private sealed record PipeRequest(string? Action, string? Resource, string? Command, string? RequestId);

    private static async Task<PipeRequest?> ReadRequestAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        using var reader = new StreamReader(pipe, System.Text.Encoding.UTF8, false, 1024, leaveOpen: true);
        var line = await reader.ReadLineAsync(ct);
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

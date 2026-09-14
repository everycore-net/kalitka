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
    private readonly ILogger<Worker> _log;
    private string _agentId = "";

    public Worker(IOptions<AgentConfig> cfg, CoreClient core, ILogger<Worker> log)
    {
        _cfg = cfg.Value;
        _core = core;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
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
        if (req is null || string.IsNullOrWhiteSpace(req.Resource))
        {
            await WriteAsync(pipe, new { status = 400, error = "bad-request" }, ct);
            return;
        }

        _log.LogInformation("Request from {Account} (sid {Sid}) for {Resource}", caller.Account, caller.Sid, req.Resource);
        var result = await _core.RaiseAsync(_agentId, caller, req.Resource, req.Command, ct);
        await WriteAsync(pipe, new { status = result.Status, id = result.Id, state = result.State }, ct);
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

    private sealed record PipeRequest(string Resource, string? Command);

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

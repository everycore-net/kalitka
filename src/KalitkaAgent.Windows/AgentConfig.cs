namespace KalitkaAgent;

/// <summary>
/// The Windows agent's configuration (bound from the <c>Kalitka</c> section). Deliberately
/// small for the thin slice: where Core is, what the local pipe is called, which CNG key to
/// use, and where the enrollment token / persisted agent id live.
/// </summary>
public sealed class AgentConfig
{
    /// <summary>Base URL of Kalitka Core, e.g. <c>https://gate.everyco.re</c> or, for the
    /// dev loop, <c>http://localhost:8080</c>.</summary>
    public string CoreUrl { get; set; } = "http://localhost:8080";

    /// <summary>The local named pipe untrusted user processes connect to. Local IPC only —
    /// never a network endpoint.</summary>
    public string PipeName { get; set; } = "kalitka-agent";

    /// <summary>How many pipe instances serve concurrently, so one slow or stalled client cannot
    /// block everyone. A small pool is plenty — approvals are human-paced.</summary>
    public int PipeInstances { get; set; } = 4;

    /// <summary>Once a client connects, the whole exchange (read the request, act, reply) must finish
    /// within this many seconds, or the connection is dropped. Without it, a client that connects and
    /// sends nothing would hold an instance open until the service restarts — a trivial local DoS.</summary>
    public int PipeConnectionTimeoutSeconds { get; set; } = 10;

    /// <summary>The largest request line the pipe will read before rejecting it. Requests are a single
    /// small JSON line; this bounds a client that streams without ever sending a newline.</summary>
    public int PipeMaxRequestBytes { get; set; } = 8192;

    /// <summary>The persisted CNG key name. The private key lives in the platform provider
    /// (TPM when present); only the SPKI ever leaves it.</summary>
    public string KeyName { get; set; } = "kalitka-agent-signing";

    /// <summary>Where the agent persists what it learns at enrollment (its agent id). Defaults
    /// under ProgramData so it survives restarts and is machine- not user-scoped.</summary>
    public string StatePath { get; set; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Kalitka", "agent.json");

    /// <summary>Write-ahead journal of active RDP leases, so a restart removes expired
    /// memberships and re-asserts valid ones. Machine-scoped under ProgramData.</summary>
    public string RdpJournalPath { get; set; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Kalitka", "rdp-leases.json");

    /// <summary>A one-time enrollment token, minted by a Core admin, used once on first run
    /// to register this agent's public key. Consumed then ignored. Empty once enrolled.</summary>
    public string EnrollmentToken { get; set; } = "";

    /// <summary>RDP enforcement model. <c>false</c> (default) is soft mode: add the subject to
    /// Remote Desktop Users on grant, remove on expiry — honest but fail-open. <c>true</c> is hard
    /// mode: the subject sits in a Kalitka-owned deny group carrying
    /// <c>SeDenyRemoteInteractiveLogonRight</c>, so login is refused by default; a grant lifts them
    /// out, expiry puts them back. Fail-closed, and requires the agent to run with the rights to
    /// change local groups and local policy.</summary>
    public bool RdpHardMode { get; set; }

    /// <summary>The Kalitka-owned deny group used in hard mode. Created if missing and granted the
    /// deny-logon right at startup. Members are default-denied RDP until a grant lifts them out.</summary>
    public string DenyGroupName { get; set; } = "Kalitka-Gated";

    /// <summary>Watch the Security log for denied RDP logons (4625, logon-type-not-granted) and raise
    /// an approval automatically, so the person needs no client — they just try to connect. Off by
    /// default; reading the Security log needs the agent to run as SYSTEM (or Event Log Readers).</summary>
    public bool RdpWatch { get; set; }
}

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

    /// <summary>The persisted CNG key name. The private key lives in the platform provider
    /// (TPM when present); only the SPKI ever leaves it.</summary>
    public string KeyName { get; set; } = "kalitka-agent-signing";

    /// <summary>Where the agent persists what it learns at enrollment (its agent id). Defaults
    /// under ProgramData so it survives restarts and is machine- not user-scoped.</summary>
    public string StatePath { get; set; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Kalitka", "agent.json");

    /// <summary>A one-time enrollment token, minted by a Core admin, used once on first run
    /// to register this agent's public key. Consumed then ignored. Empty once enrolled.</summary>
    public string EnrollmentToken { get; set; } = "";
}

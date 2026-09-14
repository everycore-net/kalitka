using System.Text.Json;

namespace KalitkaMcp;

/// <summary>Configuration for the control-plane MCP server, bound from the <c>Kalitka</c>
/// section (env vars <c>Kalitka__*</c> work too, which is how an MCP host usually passes it).</summary>
public sealed class McpConfig
{
    /// <summary>Base URL of Kalitka Core, e.g. <c>https://gate.everyco.re</c>.</summary>
    public string CoreUrl { get; set; } = "http://localhost:8080";

    /// <summary>PKCS#8 signing-key file. The private key never leaves it.</summary>
    public string KeyPath { get; set; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "kalitka-mcp", "key.p8");

    /// <summary>Where the assigned agent id is remembered across restarts.</summary>
    public string StatePath { get; set; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "kalitka-mcp", "state.json");

    /// <summary>One-time enrollment token from a Core admin, used once on first run.</summary>
    public string EnrollmentToken { get; set; } = "";
}

/// <summary>What the server remembers across restarts — just the public agent id; the
/// credential is the key file.</summary>
public sealed class McpState
{
    public string AgentId { get; set; } = "";

    public static McpState Load(string path)
    {
        try { return JsonSerializer.Deserialize<McpState>(File.ReadAllText(path)) ?? new(); }
        catch (IOException) { return new(); }
        catch (JsonException) { return new(); }
        catch (UnauthorizedAccessException) { return new(); }
    }

    public void Save(string path)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        File.WriteAllText(path, JsonSerializer.Serialize(this));
    }
}

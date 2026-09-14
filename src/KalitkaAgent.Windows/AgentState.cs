using System.Text.Json;

namespace KalitkaAgent;

/// <summary>What the agent has learned and must remember across restarts — for the thin slice
/// just the agent id it was assigned at enrollment. Persisted next to nothing secret: the
/// private key stays in the CNG provider, so this file holds only a public identifier.</summary>
public sealed class AgentState
{
    public string AgentId { get; set; } = "";

    public static AgentState Load(string path)
    {
        try { return JsonSerializer.Deserialize<AgentState>(File.ReadAllText(path)) ?? new(); }
        catch (IOException) { return new(); }
        catch (JsonException) { return new(); }
        catch (UnauthorizedAccessException) { return new(); }
    }

    public void Save(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, JsonSerializer.Serialize(this));
    }
}

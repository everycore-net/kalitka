namespace KalitkaAgent;

/// <summary>Small SID predicates shared by the Security-log parsers.</summary>
public static class Sids
{
    /// <summary>A real local or domain account SID (the S-1-5-21-&lt;domain&gt;-&lt;rid&gt; shape),
    /// not a null/anonymous or service well-known SID — we only ever act for a person who could
    /// actually be approved and granted.</summary>
    public static bool IsAccount(string? sid) =>
        !string.IsNullOrWhiteSpace(sid) && sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase);
}

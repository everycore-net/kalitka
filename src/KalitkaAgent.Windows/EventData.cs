using System.Xml.Linq;

namespace KalitkaAgent;

/// <summary>Pulls the named <c>EventData</c> fields out of a Windows event's XML. Static and pure (no
/// event-log dependency), so it is tested against a real event shape without a live log — shared by the
/// RDP logoff watcher.</summary>
public static class EventData
{
    public static IReadOnlyDictionary<string, string> Parse(string xml)
    {
        var dict = new Dictionary<string, string>(StringComparer.Ordinal);
        var doc = XDocument.Parse(xml);
        var ns = doc.Root!.Name.Namespace;
        foreach (var data in doc.Descendants(ns + "Data"))
        {
            var name = data.Attribute("Name")?.Value;
            if (name is not null) dict[name] = data.Value;
        }
        return dict;
    }
}

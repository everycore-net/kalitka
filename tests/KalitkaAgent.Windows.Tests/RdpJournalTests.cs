using KalitkaAgent;
using Xunit;

namespace KalitkaAgent.Windows.Tests;

/// <summary>
/// The RDP lease journal is the one durable thing in the agent, so its failure modes matter more than
/// its happy path: an atomic write (no truncated file after a crash), a missing file that reads empty,
/// and a corrupt file that reads as <b>unknown</b> (throws) — never silently as "no leases", which
/// would strand active memberships and leave access forever.
/// </summary>
public class RdpJournalTests
{
    private static string TempPath() => Path.Combine(Path.GetTempPath(), "rdp-jrn-" + Guid.NewGuid().ToString("N") + ".json");

    private static RdpLease Lease(string session) =>
        new(session, "S-1-5-21-1-2-3-1001", "CONTOSO\\anna", DateTimeOffset.UtcNow.AddMinutes(30));

    [Fact]
    public void A_missing_journal_reads_empty()
    {
        var p = TempPath();
        Assert.Empty(new RdpJournal(p).All());   // nothing granted yet, legitimately
    }

    [Fact]
    public void A_lease_round_trips_and_leaves_no_temp_file()
    {
        var p = TempPath();
        try
        {
            new RdpJournal(p).Upsert(Lease("s1"));
            var back = new RdpJournal(p).All();
            Assert.Single(back);
            Assert.Equal("s1", back[0].SessionId);
            Assert.False(File.Exists(p + ".tmp"));   // atomic replace/move cleaned the temp up
        }
        finally { File.Delete(p); }
    }

    [Fact]
    public void A_corrupt_journal_reads_as_unknown_not_empty()
    {
        var p = TempPath();
        try
        {
            File.WriteAllText(p, "{ this is not valid json");
            Assert.Throws<JournalUnreadableException>(() => new RdpJournal(p).All());
        }
        finally { File.Delete(p); }
    }
}

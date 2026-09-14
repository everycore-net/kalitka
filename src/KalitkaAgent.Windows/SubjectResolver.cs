using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace KalitkaAgent;

/// <summary>The caller as the OS sees it, taken from the pipe's client token — never from
/// anything the caller typed. <see cref="Sid"/> is the stable identity; <see cref="User"/> is
/// the beneficiary the request must be for; <see cref="SubjectIdentity"/> is the machine-
/// readable label Core matches against operator identities and asserts for approval.</summary>
public sealed record CallerSubject(string Sid, string Account, string User, string SubjectIdentity);

/// <summary>
/// Resolves who is on the other end of the pipe by impersonating the client token and reading
/// its Windows identity. This is the entire reason the Windows agent may assert a subject: the
/// SID comes from the login session the OS authenticated, so <c>subject.assert</c> is honest —
/// a generic CLI, which could only echo a caller-typed string, must never carry it.
/// </summary>
[SupportedOSPlatform("windows")]
public static class SubjectResolver
{
    public static CallerSubject Resolve(NamedPipeServerStream pipe)
    {
        CallerSubject? caller = null;
        pipe.RunAsClient(() =>
        {
            using var id = WindowsIdentity.GetCurrent();
            var sid = id.User?.Value ?? throw new InvalidOperationException("client token has no SID");
            var account = id.Name;   // e.g. CONTOSO\anna or MACHINE\local
            var user = account.Contains('\\') ? account[(account.LastIndexOf('\\') + 1)..] : account;
            // os:<account> so the beneficiary tail (after the last '\') is the plain user, which
            // is what Core's beneficiary check compares to the request's `user`.
            caller = new CallerSubject(sid, account, user, "os:" + account);
        });
        return caller!;
    }
}

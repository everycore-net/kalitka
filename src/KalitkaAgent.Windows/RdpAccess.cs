using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Extensions.Logging;

namespace KalitkaAgent;

/// <summary>
/// Makes a subject able or unable to sign in over RDP. This is the one thing that differs between
/// the two enforcement models, so it is factored out of <see cref="RdpEnforcer"/> (which owns the
/// lease lifecycle, journal and session teardown regardless of model):
/// <list type="bullet">
///   <item><b>Soft</b> (allow-list): the person is not in Remote Desktop Users by default; a grant
///     adds them, expiry removes them. Honest but fail-open — nothing stops a login the group
///     already allows by other means.</item>
///   <item><b>Hard</b> (deny-list): the person is in a Kalitka-owned group that carries
///     <c>SeDenyRemoteInteractiveLogonRight</c>, so by default their login is refused; a grant
///     lifts them out of the deny group, expiry puts them back. Default-deny, fail-closed.</item>
/// </list>
/// <see cref="Grant"/>/<see cref="Deny"/> are idempotent so a reconcile can re-assert freely.
/// </summary>
public interface IRdpAccess
{
    /// <summary>One-time setup at startup (idempotent). Hard mode ensures the deny group exists and
    /// carries the deny-logon right; soft mode has nothing to do.</summary>
    void Initialize();
    /// <summary>Make the subject able to sign in over RDP.</summary>
    void Grant(SecurityIdentifier sid);
    /// <summary>Make the subject unable to sign in over RDP.</summary>
    void Deny(SecurityIdentifier sid);
}

/// <summary>Soft mode: grant = add to Remote Desktop Users, deny = remove.</summary>
[SupportedOSPlatform("windows")]
public sealed class AllowListAccess : IRdpAccess
{
    private readonly ILocalGroup _rdpUsers;
    public AllowListAccess(ILocalGroup rdpUsers) => _rdpUsers = rdpUsers;

    public void Initialize() { /* Remote Desktop Users always exists; nothing to provision */ }
    public void Grant(SecurityIdentifier sid) => _rdpUsers.Add(sid);
    public void Deny(SecurityIdentifier sid) => _rdpUsers.Remove(sid);
}

/// <summary>
/// Hard mode: default-deny via a Kalitka-owned group holding <c>SeDenyRemoteInteractiveLogonRight</c>.
/// Grant lifts the subject out of the deny group; deny puts them back. The precondition for this to
/// gate a given person is that they are in the deny group at rest — <see cref="Deny"/> restores that
/// after every lease, so once Kalitka has mediated one login the subject stays default-denied.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DenyListAccess : IRdpAccess
{
    private readonly ILocalGroup _denyGroup;
    private readonly ILsaPolicy _lsa;
    private readonly ILogger<DenyListAccess> _log;

    public DenyListAccess(ILocalGroup denyGroup, ILsaPolicy lsa, ILogger<DenyListAccess> log)
    {
        _denyGroup = denyGroup;
        _lsa = lsa;
        _log = log;
    }

    public void Initialize()
    {
        _denyGroup.EnsureExists();
        _lsa.GrantPrivilege(_denyGroup.GroupSid(), LsaRights.DenyRemoteInteractiveLogon);
        _log.LogInformation("Hard mode: deny group ensured and granted {Right}", LsaRights.DenyRemoteInteractiveLogon);
    }

    // Grant lifts out of the deny group; deny returns to it. Inverted from soft mode by design.
    public void Grant(SecurityIdentifier sid) => _denyGroup.Remove(sid);
    public void Deny(SecurityIdentifier sid) => _denyGroup.Add(sid);
}

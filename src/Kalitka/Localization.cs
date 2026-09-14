using System.Globalization;

namespace Kalitka;

/// <summary>The languages the visitor-facing pages speak. English is the fallback.</summary>
public enum Lang { En, De, Ru }

/// <summary>
/// Tiny, dependency-free localisation for the pages a visitor (or an e-mail
/// approver) sees. The language is negotiated from the browser's
/// <c>Accept-Language</c> header — no cookie, no state — and every user-visible
/// string is looked up from a per-language <see cref="Strings"/> bundle. The admin
/// control plane stays English (operators, not end users).
/// </summary>
public static class L10n
{
    /// <summary>Pick the best of en/de/ru from an <c>Accept-Language</c> header,
    /// honouring the <c>q=</c> weights; anything unrecognised falls back to English.</summary>
    public static Lang Negotiate(string? acceptLanguage)
    {
        if (string.IsNullOrWhiteSpace(acceptLanguage)) return Lang.En;

        var best = Lang.En;
        var bestQ = -1.0;
        foreach (var part in acceptLanguage.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var seg = part.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var primary = seg[0].Split('-', 2)[0].ToLowerInvariant();
            var lang = primary switch { "de" => Lang.De, "ru" => Lang.Ru, "en" => Lang.En, _ => (Lang?)null };
            if (lang is null) continue;

            var q = 1.0;
            foreach (var p in seg)
                if (p.StartsWith("q=", StringComparison.OrdinalIgnoreCase)
                    && double.TryParse(p.AsSpan(2), NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed))
                    q = parsed;

            if (q > bestQ) { bestQ = q; best = lang.Value; }
        }
        return best;
    }

    public static Strings For(Lang lang) => lang switch { Lang.De => De, Lang.Ru => Ru, _ => En };

    private static readonly Strings En = new()
    {
        Code = "en",
        DocTitle = "Access",
        Tagline = "Knock. Approve. Enter.",
        TargetLabel = "Target",
        SignInGoogle = "Sign in with Google",
        SignInPasskey = "Sign in with a passkey",
        RememberDevice = "Remember this device",
        ContinueIn = "Continue",
        OrAsk = "or ask to be let in",
        NamePlaceholder = "Name or e-mail",
        Ask = "Ask",
        ByHand = "Someone has to let you in by hand. After that you continue to the login.",
        InvalidInput = "Please enter something valid.",
        Asked = "Asked",
        WaitingMsg = "Waiting to be let in…",
        ApprovedContinuing = "Approved, continuing…",
        RefusedShort = "Refused.",
        ExpiredReload = "Expired. Reload to ask again.",
        ResourceLabel = "Resource",
        SaysLabel = "Says",
        ApproveAccessTitle = "Approve access?",
        DenyAccessTitle = "Deny access?",
        ConfirmApprove = "Confirm: Approve",
        ConfirmDeny = "Confirm: Deny",
        OnceExpires = "This link works once and then expires.",
        ErrorTitle = "Error",
        SigninInvalid = "Sign-in was not valid. Please try again.",
        RefusedTitle = "Refused",
        GoogleNotPermitted = "This Google account is not permitted.",
        AccessDenied = "Access denied.",
        LinkInvalidTitle = "Link invalid",
        LinkInvalidText = "This link is not valid or has expired.",
        NothingToDoTitle = "Nothing to do",
        NothingToDoText = "That request is no longer waiting — it may already have been decided or expired.",
        AlreadyUsedTitle = "Already used",
        AlreadyUsedText = "This link has already been used.",
        DoneTitle = "Done",
        ActionApproved = "Approved. The visitor may continue.",
        ActionDenied = "Denied.",
        ActionAlreadyDecided = "That request was already decided.",
        ActionNoLongerWaiting = "That request is no longer waiting — it may have expired.",
        NotFoundTitle = "404",
        NotFoundText = "Nothing here.",
        SourceLabel = "Source",
    };

    private static readonly Strings De = new()
    {
        Code = "de",
        DocTitle = "Zugang",
        Tagline = "Anklopfen. Freigeben. Eintreten.",
        TargetLabel = "Ziel",
        SignInGoogle = "Mit Google anmelden",
        SignInPasskey = "Mit Passkey anmelden",
        RememberDevice = "Dieses Gerät merken",
        ContinueIn = "Weiter",
        OrAsk = "oder um Einlass bitten",
        NamePlaceholder = "Name oder E-Mail",
        Ask = "Anfragen",
        ByHand = "Jemand muss dich von Hand einlassen. Danach geht es weiter zur Anmeldung.",
        InvalidInput = "Bitte etwas Gültiges eingeben.",
        Asked = "Angefragt",
        WaitingMsg = "Warte auf Einlass …",
        ApprovedContinuing = "Genehmigt, weiter …",
        RefusedShort = "Abgelehnt.",
        ExpiredReload = "Abgelaufen. Zum erneuten Anfragen neu laden.",
        ResourceLabel = "Ressource",
        SaysLabel = "Angabe",
        ApproveAccessTitle = "Zugang genehmigen?",
        DenyAccessTitle = "Zugang verweigern?",
        ConfirmApprove = "Bestätigen: Genehmigen",
        ConfirmDeny = "Bestätigen: Verweigern",
        OnceExpires = "Dieser Link funktioniert einmal und läuft dann ab.",
        ErrorTitle = "Fehler",
        SigninInvalid = "Die Anmeldung war ungültig. Bitte erneut versuchen.",
        RefusedTitle = "Abgelehnt",
        GoogleNotPermitted = "Dieses Google-Konto ist nicht zugelassen.",
        AccessDenied = "Zugriff verweigert.",
        LinkInvalidTitle = "Link ungültig",
        LinkInvalidText = "Dieser Link ist ungültig oder abgelaufen.",
        NothingToDoTitle = "Nichts zu tun",
        NothingToDoText = "Diese Anfrage wartet nicht mehr — sie wurde vielleicht schon entschieden oder ist abgelaufen.",
        AlreadyUsedTitle = "Bereits verwendet",
        AlreadyUsedText = "Dieser Link wurde bereits verwendet.",
        DoneTitle = "Fertig",
        ActionApproved = "Genehmigt. Die Besucherin oder der Besucher darf fortfahren.",
        ActionDenied = "Verweigert.",
        ActionAlreadyDecided = "Diese Anfrage wurde bereits entschieden.",
        ActionNoLongerWaiting = "Diese Anfrage wartet nicht mehr — sie ist vielleicht abgelaufen.",
        NotFoundTitle = "404",
        NotFoundText = "Hier ist nichts.",
        SourceLabel = "Quelltext",
    };

    private static readonly Strings Ru = new()
    {
        Code = "ru",
        DocTitle = "Доступ",
        Tagline = "Постучись. Одобри. Войди.",
        TargetLabel = "Цель",
        SignInGoogle = "Войти через Google",
        SignInPasskey = "Войти по passkey",
        RememberDevice = "Запомнить это устройство",
        ContinueIn = "Продолжить",
        OrAsk = "или попросить впустить",
        NamePlaceholder = "Имя или e-mail",
        Ask = "Запросить",
        ByHand = "Кто-то должен впустить вас вручную. После этого вы продолжите ко входу.",
        InvalidInput = "Пожалуйста, введите корректное значение.",
        Asked = "Запрошено",
        WaitingMsg = "Ожидание, пока впустят…",
        ApprovedContinuing = "Одобрено, продолжаем…",
        RefusedShort = "Отказано.",
        ExpiredReload = "Истекло. Обновите страницу, чтобы запросить снова.",
        ResourceLabel = "Ресурс",
        SaysLabel = "Указано",
        ApproveAccessTitle = "Разрешить доступ?",
        DenyAccessTitle = "Отклонить доступ?",
        ConfirmApprove = "Подтвердить: разрешить",
        ConfirmDeny = "Подтвердить: отклонить",
        OnceExpires = "Эта ссылка срабатывает один раз и затем становится недействительной.",
        ErrorTitle = "Ошибка",
        SigninInvalid = "Вход не прошёл проверку. Пожалуйста, попробуйте снова.",
        RefusedTitle = "Отказано",
        GoogleNotPermitted = "Этот аккаунт Google не разрешён.",
        AccessDenied = "Доступ запрещён.",
        LinkInvalidTitle = "Ссылка недействительна",
        LinkInvalidText = "Эта ссылка недействительна или истекла.",
        NothingToDoTitle = "Нечего делать",
        NothingToDoText = "Этот запрос больше не ожидает — возможно, он уже обработан или истёк.",
        AlreadyUsedTitle = "Уже использовано",
        AlreadyUsedText = "Эта ссылка уже была использована.",
        DoneTitle = "Готово",
        ActionApproved = "Одобрено. Посетитель может продолжить.",
        ActionDenied = "Отклонено.",
        ActionAlreadyDecided = "Этот запрос уже был решён.",
        ActionNoLongerWaiting = "Этот запрос больше не ожидает — возможно, он истёк.",
        NotFoundTitle = "404",
        NotFoundText = "Здесь ничего нет.",
        SourceLabel = "Исходный код",
    };
}

/// <summary>Every user-visible string on the visitor/approver pages, one bundle per
/// language. Init-only so the three instances read as plain translation tables.</summary>
public sealed record Strings
{
    public required string Code { get; init; }   // BCP-47 primary tag for <html lang>
    public required string DocTitle { get; init; }
    public required string Tagline { get; init; }
    public required string TargetLabel { get; init; }
    public required string SignInGoogle { get; init; }
    public required string SignInPasskey { get; init; }
    public required string RememberDevice { get; init; }
    public required string ContinueIn { get; init; }
    public required string OrAsk { get; init; }
    public required string NamePlaceholder { get; init; }
    public required string Ask { get; init; }
    public required string ByHand { get; init; }
    public required string InvalidInput { get; init; }
    public required string Asked { get; init; }
    public required string WaitingMsg { get; init; }
    public required string ApprovedContinuing { get; init; }
    public required string RefusedShort { get; init; }
    public required string ExpiredReload { get; init; }
    public required string ResourceLabel { get; init; }
    public required string SaysLabel { get; init; }
    public required string ApproveAccessTitle { get; init; }
    public required string DenyAccessTitle { get; init; }
    public required string ConfirmApprove { get; init; }
    public required string ConfirmDeny { get; init; }
    public required string OnceExpires { get; init; }
    public required string ErrorTitle { get; init; }
    public required string SigninInvalid { get; init; }
    public required string RefusedTitle { get; init; }
    public required string GoogleNotPermitted { get; init; }
    public required string AccessDenied { get; init; }
    public required string LinkInvalidTitle { get; init; }
    public required string LinkInvalidText { get; init; }
    public required string NothingToDoTitle { get; init; }
    public required string NothingToDoText { get; init; }
    public required string AlreadyUsedTitle { get; init; }
    public required string AlreadyUsedText { get; init; }
    public required string DoneTitle { get; init; }
    public required string ActionApproved { get; init; }
    public required string ActionDenied { get; init; }
    public required string ActionAlreadyDecided { get; init; }
    public required string ActionNoLongerWaiting { get; init; }
    public required string NotFoundTitle { get; init; }
    public required string NotFoundText { get; init; }
    public required string SourceLabel { get; init; }
}

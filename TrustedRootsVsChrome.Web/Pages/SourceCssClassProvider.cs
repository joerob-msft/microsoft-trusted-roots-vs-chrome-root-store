using System;
using System.Collections.Generic;

namespace TrustedRootsVsChrome.Web.Pages;

internal static class SourceCssClassProvider
{
    private static readonly IReadOnlyDictionary<string, string> SourceCssClassMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["Current User / Trusted Root"] = "source-pill--current-user-trusted-root",
        ["Current User / Third-Party Root"] = "source-pill--current-user-third-party",
        ["Local Machine / Trusted Root"] = "source-pill--local-machine-trusted-root",
        ["Local Machine / Third-Party Root"] = "source-pill--local-machine-third-party",
        ["Local Machine / Group Policy Root"] = "source-pill--local-machine-group-policy",
        ["Local Machine / Enterprise Root"] = "source-pill--local-machine-enterprise",
        ["Microsoft Trusted Root Program"] = "source-pill--trusted-program",
        ["Chrome Root Store"] = "source-pill--chrome-root"
    };

    public static string GetSourceCssClass(string source)
        => SourceCssClassMap.TryGetValue(source, out var cssClass)
            ? cssClass
            : "source-pill--other";
}
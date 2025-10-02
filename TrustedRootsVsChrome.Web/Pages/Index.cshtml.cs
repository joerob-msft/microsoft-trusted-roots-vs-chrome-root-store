using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using TrustedRootsVsChrome.Web.Models;
using TrustedRootsVsChrome.Web.Services;

namespace TrustedRootsVsChrome.Web.Pages;

public class IndexModel : PageModel
{
    private readonly CertificateComparisonService _comparisonService;

    private static readonly IReadOnlyDictionary<string, string> SourceCssClassMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["Current User / Trusted Root"] = "source-pill--current-user-trusted-root",
        ["Current User / Third-Party Root"] = "source-pill--current-user-third-party",
        ["Local Machine / Trusted Root"] = "source-pill--local-machine-trusted-root",
        ["Local Machine / Third-Party Root"] = "source-pill--local-machine-third-party",
        ["Local Machine / Group Policy Root"] = "source-pill--local-machine-group-policy",
        ["Local Machine / Enterprise Root"] = "source-pill--local-machine-enterprise",
        ["Microsoft Trusted Root Program"] = "source-pill--trusted-program"
    };

    public CertificateComparisonResult? ComparisonResult { get; private set; }

    [BindProperty(SupportsGet = true)]
    public bool ExcludeMicrosoftRoots { get; set; } = true;

    public IndexModel(CertificateComparisonService comparisonService)
        => _comparisonService = comparisonService;

    public async Task OnGetAsync(CancellationToken cancellationToken)
        => ComparisonResult = await _comparisonService.GetDifferencesAsync(ExcludeMicrosoftRoots, cancellationToken);

    public static string GetSourceCssClass(string source)
        => SourceCssClassMap.TryGetValue(source, out var cssClass)
            ? cssClass
            : "source-pill--other";
}

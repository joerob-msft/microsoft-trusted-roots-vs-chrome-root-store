using Microsoft.AspNetCore.Mvc.RazorPages;
using TrustedRootsVsChrome.Web.Models;
using TrustedRootsVsChrome.Web.Services;

namespace TrustedRootsVsChrome.Web.Pages;

public class IndexModel : PageModel
{
    private readonly CertificateComparisonService _comparisonService;

    public CertificateComparisonResult? ComparisonResult { get; private set; }

    public IndexModel(CertificateComparisonService comparisonService)
        => _comparisonService = comparisonService;

    public async Task OnGetAsync(CancellationToken cancellationToken)
        => ComparisonResult = await _comparisonService.GetDifferencesAsync(cancellationToken);
}

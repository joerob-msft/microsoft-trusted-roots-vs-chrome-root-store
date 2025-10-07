using Microsoft.AspNetCore.Mvc.RazorPages;
using TrustedRootsVsChrome.Web.Models;
using TrustedRootsVsChrome.Web.Services;

namespace TrustedRootsVsChrome.Web.Pages;

public class IndexModel : PageModel
{
    private readonly CertificateComparisonService _comparisonService;
    private readonly ICertificateRefreshStatusProvider _statusProvider;

    public CertificateComparisonResult? ComparisonResult { get; private set; }
    public CertificateRefreshStatus RefreshStatus { get; private set; } = CertificateRefreshStatus.Empty;

    public IndexModel(CertificateComparisonService comparisonService, ICertificateRefreshStatusProvider statusProvider)
    {
        _comparisonService = comparisonService;
        _statusProvider = statusProvider;
    }

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        ComparisonResult = await _comparisonService.GetDifferencesAsync(cancellationToken);
        RefreshStatus = _statusProvider.GetStatus();
    }
}

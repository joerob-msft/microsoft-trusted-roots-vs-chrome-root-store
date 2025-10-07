using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TrustedRootsVsChrome.Web.Models;

namespace TrustedRootsVsChrome.Web.Services;

public sealed class CertificateComparisonService
{
    private readonly IChromeRootStoreProvider _chromeRootStoreProvider;
    private readonly IMicrosoftTrustedRootProgramProvider _microsoftTrustedRootProgramProvider;
    private readonly ILogger<CertificateComparisonService> _logger;

    public CertificateComparisonService(
        IChromeRootStoreProvider chromeRootStoreProvider,
        IMicrosoftTrustedRootProgramProvider microsoftTrustedRootProgramProvider,
        ILogger<CertificateComparisonService> logger)
    {
        _chromeRootStoreProvider = chromeRootStoreProvider;
        _microsoftTrustedRootProgramProvider = microsoftTrustedRootProgramProvider;
        _logger = logger;
    }

    public async Task<CertificateComparisonResult> GetDifferencesAsync(CancellationToken cancellationToken)
    {
        try
        {
            var chromeRoots = await _chromeRootStoreProvider.GetCertificatesAsync(cancellationToken);
            var microsoftProgramRoots = await _microsoftTrustedRootProgramProvider.GetCertificatesAsync(cancellationToken);

            var chromeThumbprints = new HashSet<string>(chromeRoots.Select(c => c.Thumbprint), StringComparer.OrdinalIgnoreCase);

            var missing = microsoftProgramRoots
                .Where(cert => !chromeThumbprints.Contains(cert.Thumbprint))
                .Select(CertificateRecordMapper.FromMicrosoftTrustedRootProgram)
                .OrderBy(record => record.Subject, StringComparer.OrdinalIgnoreCase)
                .ToList();

            return new CertificateComparisonResult
            {
                MissingInChrome = missing,
                RetrievedAtUtc = DateTime.UtcNow
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Certificate comparison failed");
            return new CertificateComparisonResult
            {
                MissingInChrome = Array.Empty<CertificateRecord>(),
                RetrievedAtUtc = DateTime.UtcNow,
                ErrorMessage = "Unable to compare certificate stores. Please retry later or check application logs."
            };
        }
    }
}
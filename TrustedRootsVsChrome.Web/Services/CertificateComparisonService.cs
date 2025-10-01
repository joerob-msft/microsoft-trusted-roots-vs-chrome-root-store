using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TrustedRootsVsChrome.Web.Models;

namespace TrustedRootsVsChrome.Web.Services;

public sealed class CertificateComparisonService
{
    private readonly IChromeRootStoreProvider _chromeRootStoreProvider;
    private readonly IWindowsTrustedRootProvider _windowsTrustedRootProvider;
    private readonly ILogger<CertificateComparisonService> _logger;

    public CertificateComparisonService(
    IChromeRootStoreProvider chromeRootStoreProvider,
    IWindowsTrustedRootProvider windowsTrustedRootProvider,
        ILogger<CertificateComparisonService> logger)
    {
        _chromeRootStoreProvider = chromeRootStoreProvider;
        _windowsTrustedRootProvider = windowsTrustedRootProvider;
        _logger = logger;
    }

    public async Task<CertificateComparisonResult> GetDifferencesAsync(CancellationToken cancellationToken)
    {
        try
        {
            var chromeRoots = await _chromeRootStoreProvider.GetCertificatesAsync(cancellationToken);
            var windowsRoots = _windowsTrustedRootProvider.GetTrustedRoots();

            var chromeThumbprints = new HashSet<string>(chromeRoots.Select(c => c.Thumbprint), StringComparer.OrdinalIgnoreCase);

            var missing = windowsRoots
                .Where(cert => !IsMicrosoftTrustAnchor(cert))
                .Where(cert => !chromeThumbprints.Contains(cert.Thumbprint))
                .Select(ToRecord)
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

    private static bool IsMicrosoftTrustAnchor(X509Certificate2 certificate)
    {
        static bool ContainsMicrosoft(string? value) =>
            !string.IsNullOrEmpty(value) && value.Contains("Microsoft", StringComparison.OrdinalIgnoreCase);

        return ContainsMicrosoft(certificate.Subject) || ContainsMicrosoft(certificate.Issuer);
    }

    private static CertificateRecord ToRecord(X509Certificate2 certificate)
        => new(
            certificate.Subject,
            certificate.Issuer,
            certificate.Thumbprint,
            certificate.NotBefore.ToUniversalTime(),
            certificate.NotAfter.ToUniversalTime(),
            certificate.Version,
            string.IsNullOrWhiteSpace(certificate.FriendlyName) ? null : certificate.FriendlyName);
}
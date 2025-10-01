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

    public async Task<CertificateComparisonResult> GetDifferencesAsync(bool excludeMicrosoftTrustAnchors, CancellationToken cancellationToken)
    {
        try
        {
            var chromeRoots = await _chromeRootStoreProvider.GetCertificatesAsync(cancellationToken);
            var windowsRoots = _windowsTrustedRootProvider.GetTrustedRoots();

            var chromeThumbprints = new HashSet<string>(chromeRoots.Select(c => c.Thumbprint), StringComparer.OrdinalIgnoreCase);

            var missing = windowsRoots
                .Where(root => !excludeMicrosoftTrustAnchors || !IsMicrosoftTrustAnchor(root.Certificate))
                .Where(root => !chromeThumbprints.Contains(root.Certificate.Thumbprint))
                .Select(ToRecord)
                .OrderBy(record => record.Subject, StringComparer.OrdinalIgnoreCase)
                .ToList();

            return new CertificateComparisonResult
            {
                MissingInChrome = missing,
                RetrievedAtUtc = DateTime.UtcNow,
                ExcludingMicrosoftRoots = excludeMicrosoftTrustAnchors
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Certificate comparison failed");
            return new CertificateComparisonResult
            {
                MissingInChrome = Array.Empty<CertificateRecord>(),
                RetrievedAtUtc = DateTime.UtcNow,
                ErrorMessage = "Unable to compare certificate stores. Please retry later or check application logs.",
                ExcludingMicrosoftRoots = excludeMicrosoftTrustAnchors
            };
        }
    }

    private static bool IsMicrosoftTrustAnchor(X509Certificate2 certificate)
    {
        static bool HasMicrosoftMarker(string? value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return false;
            }

            return value.Contains("Microsoft", StringComparison.OrdinalIgnoreCase)
                || value.Contains("ameroot", StringComparison.OrdinalIgnoreCase)
                || value.Contains("ame root", StringComparison.OrdinalIgnoreCase)
                || value.Contains("ame-root", StringComparison.OrdinalIgnoreCase);
        }

        return HasMicrosoftMarker(certificate.Subject)
            || HasMicrosoftMarker(certificate.Issuer)
            || HasMicrosoftMarker(certificate.FriendlyName);
    }

    private static CertificateRecord ToRecord(WindowsTrustedRoot root)
    {
        var certificate = root.Certificate;

        return new CertificateRecord(
            certificate.Subject,
            certificate.Issuer,
            certificate.Thumbprint,
            certificate.NotBefore.ToUniversalTime(),
            certificate.NotAfter.ToUniversalTime(),
            certificate.Version,
            root.Sources,
            string.IsNullOrWhiteSpace(certificate.FriendlyName) ? null : certificate.FriendlyName);
    }
}
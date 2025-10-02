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
    private static readonly IReadOnlyCollection<string> DefaultProgramSource = new[] { "Microsoft Trusted Root Program" };

    private readonly IChromeRootStoreProvider _chromeRootStoreProvider;
    private readonly IMicrosoftTrustedRootProgramProvider _microsoftTrustedRootProgramProvider;
    private readonly IWindowsTrustedRootProvider _windowsTrustedRootProvider;
    private readonly ILogger<CertificateComparisonService> _logger;

    public CertificateComparisonService(
        IChromeRootStoreProvider chromeRootStoreProvider,
        IMicrosoftTrustedRootProgramProvider microsoftTrustedRootProgramProvider,
        IWindowsTrustedRootProvider windowsTrustedRootProvider,
        ILogger<CertificateComparisonService> logger)
    {
        _chromeRootStoreProvider = chromeRootStoreProvider;
        _microsoftTrustedRootProgramProvider = microsoftTrustedRootProgramProvider;
        _windowsTrustedRootProvider = windowsTrustedRootProvider;
        _logger = logger;
    }

    public async Task<CertificateComparisonResult> GetDifferencesAsync(bool excludeMicrosoftTrustAnchors, CancellationToken cancellationToken)
    {
        try
        {
            var chromeRoots = await _chromeRootStoreProvider.GetCertificatesAsync(cancellationToken);
            var microsoftProgramRoots = await _microsoftTrustedRootProgramProvider.GetCertificatesAsync(cancellationToken);
            var windowsRoots = _windowsTrustedRootProvider.GetTrustedRoots();

            var windowsByThumbprint = windowsRoots.ToDictionary(root => root.Certificate.Thumbprint, root => root, StringComparer.OrdinalIgnoreCase);

            var chromeThumbprints = new HashSet<string>(chromeRoots.Select(c => c.Thumbprint), StringComparer.OrdinalIgnoreCase);

            var missing = microsoftProgramRoots
                .Where(cert => !excludeMicrosoftTrustAnchors || !IsMicrosoftTrustAnchor(cert))
                .Where(cert => !chromeThumbprints.Contains(cert.Thumbprint))
                .Select(cert =>
                {
                    windowsByThumbprint.TryGetValue(cert.Thumbprint, out var windowsRoot);
                    var sources = BuildSources(windowsRoot);
                    return ToRecord(cert, sources);
                })
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

    private static IReadOnlyCollection<string> BuildSources(WindowsTrustedRoot? windowsRoot)
    {
        if (windowsRoot is null || windowsRoot.Sources.Count == 0)
        {
            return DefaultProgramSource;
        }

        return windowsRoot.Sources
            .Concat(DefaultProgramSource)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static CertificateRecord ToRecord(X509Certificate2 certificate, IReadOnlyCollection<string> sources)
    {
        return new CertificateRecord(
            certificate.Subject,
            certificate.Issuer,
            certificate.Thumbprint,
            certificate.NotBefore.ToUniversalTime(),
            certificate.NotAfter.ToUniversalTime(),
            certificate.Version,
            sources,
            string.IsNullOrWhiteSpace(certificate.FriendlyName) ? null : certificate.FriendlyName);
    }
}
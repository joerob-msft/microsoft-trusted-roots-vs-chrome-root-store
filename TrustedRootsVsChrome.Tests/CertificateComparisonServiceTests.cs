using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using TrustedRootsVsChrome.Web.Models;
using TrustedRootsVsChrome.Web.Services;
using Xunit;

namespace TrustedRootsVsChrome.Tests;

public sealed class CertificateComparisonServiceTests : IDisposable
{
    private readonly List<X509Certificate2> _disposables = new();

    [Fact]
    public async Task ExcludesMicrosoftRootsFromDifferences()
    {
        var microsoftRoot = Track(CreateCertificate("CN=Microsoft Test Root"));
        var chromeRoots = new[] { microsoftRoot };
        var microsoftProgramRoots = new[] { microsoftRoot };
        var windowsRoots = Array.Empty<WindowsTrustedRoot>();

        var service = CreateService(chromeRoots, microsoftProgramRoots, windowsRoots);

        var result = await service.GetDifferencesAsync(excludeMicrosoftTrustAnchors: true, CancellationToken.None);

        Assert.Empty(result.MissingInChrome);
    }

    [Fact]
    public async Task ReturnsMicrosoftProgramCertificatesMissingFromChrome()
    {
        var sharedCert = Track(CreateCertificate("CN=Shared"));
        var uniqueCert = Track(CreateCertificate("CN=Unique"));

        var chromeRoots = new[] { sharedCert };
        var microsoftProgramRoots = new[] { sharedCert, uniqueCert };
        var windowsRoots = new[]
        {
            CreateWindowsRoot(sharedCert, "Local Machine / Trusted Root"),
            CreateWindowsRoot(uniqueCert)
        };

        var service = CreateService(chromeRoots, microsoftProgramRoots, windowsRoots);

        var result = await service.GetDifferencesAsync(excludeMicrosoftTrustAnchors: true, CancellationToken.None);

        var record = Assert.Single(result.MissingInChrome);
        Assert.Equal("CN=Unique", record.Subject);
        Assert.Contains("Microsoft Trusted Root Program", record.Sources);
    }

    [Fact]
    public async Task AugmentsSourcesWithWindowsLocationsWhenPresent()
    {
        var cert = Track(CreateCertificate("CN=Augmented"));

        var service = CreateService(
            chromeRoots: Array.Empty<X509Certificate2>(),
            microsoftProgramRoots: new[] { cert },
            windowsRoots: new[] { CreateWindowsRoot(cert, "Current User / Trusted Root", "Local Machine / Third-Party Root") });

        var result = await service.GetDifferencesAsync(excludeMicrosoftTrustAnchors: true, CancellationToken.None);

        var record = Assert.Single(result.MissingInChrome);
        Assert.Equal(3, record.Sources.Count);
        Assert.Contains("Microsoft Trusted Root Program", record.Sources);
        Assert.Contains("Current User / Trusted Root", record.Sources);
        Assert.Contains("Local Machine / Third-Party Root", record.Sources);
    }

    [Fact]
    public async Task IncludesMicrosoftRootsWhenToggleDisabled()
    {
        var microsoftRoot = Track(CreateCertificate("CN=Microsoft Test Root"));

        var service = CreateService(
            chromeRoots: Array.Empty<X509Certificate2>(),
            microsoftProgramRoots: new[] { microsoftRoot },
            windowsRoots: new[] { CreateWindowsRoot(microsoftRoot) });

        var result = await service.GetDifferencesAsync(excludeMicrosoftTrustAnchors: false, CancellationToken.None);

        var record = Assert.Single(result.MissingInChrome);
        Assert.Equal("CN=Microsoft Test Root", record.Subject);
    }

    private CertificateComparisonService CreateService(
        IReadOnlyCollection<X509Certificate2> chromeRoots,
        IReadOnlyCollection<X509Certificate2> microsoftProgramRoots,
        IReadOnlyCollection<WindowsTrustedRoot> windowsRoots)
    {
        var chromeProvider = new StubChromeProvider(chromeRoots);
        var microsoftProvider = new StubMicrosoftProvider(microsoftProgramRoots);
        var windowsProvider = new StubWindowsProvider(windowsRoots);

        return new CertificateComparisonService(
            chromeProvider,
            microsoftProvider,
            windowsProvider,
            NullLogger<CertificateComparisonService>.Instance);
    }

    private static WindowsTrustedRoot CreateWindowsRoot(X509Certificate2 certificate, params string[] sources)
        => new(certificate, sources);

    private X509Certificate2 CreateCertificate(string subjectName)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));

        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = DateTimeOffset.UtcNow.AddYears(5);

        var certificate = request.CreateSelfSigned(notBefore, notAfter);
        if (OperatingSystem.IsWindows())
        {
            certificate.FriendlyName = subjectName;
        }
        return certificate;
    }

    private X509Certificate2 Track(X509Certificate2 certificate)
    {
        _disposables.Add(certificate);
        return certificate;
    }

    public void Dispose()
    {
        foreach (var certificate in _disposables)
        {
            certificate.Dispose();
        }
        _disposables.Clear();
    }

    private sealed class StubChromeProvider : IChromeRootStoreProvider
    {
        private readonly IReadOnlyCollection<X509Certificate2> _certificates;

        public StubChromeProvider(IReadOnlyCollection<X509Certificate2> certificates)
            => _certificates = certificates;

        public Task<IReadOnlyCollection<X509Certificate2>> GetCertificatesAsync(CancellationToken cancellationToken)
            => Task.FromResult(_certificates);
    }

    private sealed class StubMicrosoftProvider : IMicrosoftTrustedRootProgramProvider
    {
        private readonly IReadOnlyCollection<X509Certificate2> _certificates;

        public StubMicrosoftProvider(IReadOnlyCollection<X509Certificate2> certificates)
            => _certificates = certificates;

        public Task<IReadOnlyCollection<X509Certificate2>> GetCertificatesAsync(CancellationToken cancellationToken)
            => Task.FromResult(_certificates);
    }

    private sealed class StubWindowsProvider : IWindowsTrustedRootProvider
    {
        private readonly IReadOnlyCollection<WindowsTrustedRoot> _roots;

        public StubWindowsProvider(IReadOnlyCollection<WindowsTrustedRoot> roots)
            => _roots = roots;

        public IReadOnlyCollection<WindowsTrustedRoot> GetTrustedRoots() => _roots;
    }
}
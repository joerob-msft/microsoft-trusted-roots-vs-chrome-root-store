using System;
using System.Collections.Generic;
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
        var windowsRoots = new[] { CreateWindowsRoot(microsoftRoot, "Local Machine / Trusted Root") };

        var service = CreateService(chromeRoots, windowsRoots);

        var result = await service.GetDifferencesAsync(excludeMicrosoftTrustAnchors: true, CancellationToken.None);

        Assert.Empty(result.MissingInChrome);
    }

    [Fact]
    public async Task ReturnsWindowsOnlyCertificates()
    {
        var sharedCert = Track(CreateCertificate("CN=Shared"));
        var windowsUnique = Track(CreateCertificate("CN=Unique"));

        var chromeRoots = new[] { sharedCert };
        var windowsRoots = new[]
        {
            CreateWindowsRoot(sharedCert, "Local Machine / Trusted Root"),
            CreateWindowsRoot(windowsUnique, "Local Machine / Trusted Root")
        };

        var service = CreateService(chromeRoots, windowsRoots);

        CertificateComparisonResult result = await service.GetDifferencesAsync(excludeMicrosoftTrustAnchors: true, CancellationToken.None);

        Assert.Single(result.MissingInChrome);
        Assert.Equal("CN=Unique", result.MissingInChrome[0].Subject);
    }

    [Fact]
    public async Task IncludesMicrosoftRootsWhenToggleDisabled()
    {
        var microsoftRoot = Track(CreateCertificate("CN=Microsoft Test Root"));
        var chromeRoots = Array.Empty<X509Certificate2>();
        var windowsRoots = new[] { CreateWindowsRoot(microsoftRoot, "Local Machine / Trusted Root") };

        var service = CreateService(chromeRoots, windowsRoots);

        CertificateComparisonResult result = await service.GetDifferencesAsync(excludeMicrosoftTrustAnchors: false, CancellationToken.None);

        Assert.Single(result.MissingInChrome);
        Assert.Equal("CN=Microsoft Test Root", result.MissingInChrome[0].Subject);
    }

    [Fact]
    public async Task RecordsSourceMetadataOnCertificate()
    {
        var unique = Track(CreateCertificate("CN=Unique"));
        var chromeRoots = Array.Empty<X509Certificate2>();
        var windowsRoots = new[] { CreateWindowsRoot(unique, "Current User / Trusted Root", "Local Machine / Third-Party Root") };

        var service = CreateService(chromeRoots, windowsRoots);

        CertificateComparisonResult result = await service.GetDifferencesAsync(excludeMicrosoftTrustAnchors: true, CancellationToken.None);

        var record = Assert.Single(result.MissingInChrome);
        Assert.Contains("Current User / Trusted Root", record.Sources);
        Assert.Contains("Local Machine / Third-Party Root", record.Sources);
    }

    private CertificateComparisonService CreateService(
        IReadOnlyCollection<X509Certificate2> chromeRoots,
        IReadOnlyCollection<WindowsTrustedRoot> windowsRoots)
    {
        var chromeProvider = new StubChromeProvider(chromeRoots);
        var windowsProvider = new StubWindowsProvider(windowsRoots);

        return new CertificateComparisonService(
            chromeProvider,
            windowsProvider,
            NullLogger<CertificateComparisonService>.Instance);
    }

    private WindowsTrustedRoot CreateWindowsRoot(X509Certificate2 certificate, params string[] sources)
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

    private sealed class StubWindowsProvider : IWindowsTrustedRootProvider
    {
        private readonly IReadOnlyCollection<WindowsTrustedRoot> _certificates;

        public StubWindowsProvider(IReadOnlyCollection<WindowsTrustedRoot> certificates)
            => _certificates = certificates;

        public IReadOnlyCollection<WindowsTrustedRoot> GetTrustedRoots() => _certificates;
    }
}
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
    public async Task ReturnsEmptyWhenChromeContainsProgramCertificate()
    {
        var microsoftRoot = Track(CreateCertificate("CN=Microsoft Test Root"));
        var chromeRoots = new[] { microsoftRoot };
        var microsoftProgramRoots = new[] { microsoftRoot };

        var service = CreateService(chromeRoots, microsoftProgramRoots);

        var result = await service.GetDifferencesAsync(CancellationToken.None);

        Assert.Empty(result.MissingInChrome);
    }

    [Fact]
    public async Task ReturnsMicrosoftProgramCertificatesMissingFromChrome()
    {
        var sharedCert = Track(CreateCertificate("CN=Shared"));
        var uniqueCert = Track(CreateCertificate("CN=Unique"));

        var chromeRoots = new[] { sharedCert };
        var microsoftProgramRoots = new[] { sharedCert, uniqueCert };

        var service = CreateService(chromeRoots, microsoftProgramRoots);

        var result = await service.GetDifferencesAsync(CancellationToken.None);

        var record = Assert.Single(result.MissingInChrome);
        Assert.Equal("CN=Unique", record.Subject);
        Assert.Contains("Microsoft Trusted Root Program", record.Sources);
        Assert.Single(record.Sources);
    }

    private CertificateComparisonService CreateService(
        IReadOnlyCollection<X509Certificate2> chromeRoots,
        IReadOnlyCollection<X509Certificate2> microsoftProgramRoots)
    {
        var chromeProvider = new StubChromeProvider(chromeRoots);
        var microsoftProvider = new StubMicrosoftProvider(microsoftProgramRoots);

        return new CertificateComparisonService(
            chromeProvider,
            microsoftProvider,
            NullLogger<CertificateComparisonService>.Instance);
    }

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
}
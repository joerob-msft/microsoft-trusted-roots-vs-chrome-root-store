using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using TrustedRootsVsChrome.Web.Services;
using Xunit;

namespace TrustedRootsVsChrome.Tests;

public sealed class MicrosoftTrustedRootProgramProviderTests
{
    [Fact]
    public async Task DownloadsFullTrustedRootCatalog()
    {
        var certificateBytes = CreateTestCertificate(out var sha256Fingerprint, out var sha1Fingerprint, out var subject);

        var csvPayload = BuildCsv(subject, sha1Fingerprint, sha256Fingerprint);

        using var handler = new StubHttpMessageHandler((request, attempt) =>
        {
            if (request.RequestUri is null)
            {
                throw new InvalidOperationException("Request URI was null");
            }

            if (string.Equals(request.RequestUri.AbsoluteUri, "https://ccadb.my.salesforce-sites.com/microsoft/IncludedCACertificateReportForMSFTCSV", StringComparison.OrdinalIgnoreCase))
            {
                var response = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(csvPayload, Encoding.UTF8)
                };
                response.Content.Headers.ContentType = new MediaTypeHeaderValue("text/csv");
                return response;
            }

            if (string.Equals(request.RequestUri.Host, "crt.sh", StringComparison.OrdinalIgnoreCase))
            {
                var response = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(certificateBytes)
                };
                response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/pkix-cert");
                return response;
            }

            throw new InvalidOperationException($"Unexpected request to {request.RequestUri}");
        });

        using var httpClient = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(5)
        };
        httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("TrustedRootsVsChrome.Tests/1.0");

        var store = new InMemoryCertificateCacheStore();
    var statusTracker = new CertificateRefreshStatusTracker();
    var provider = new MicrosoftTrustedRootProgramProvider(httpClient, store, NullLogger<MicrosoftTrustedRootProgramProvider>.Instance, statusTracker, statusTracker);

        var refreshService = (IMicrosoftTrustedRootProgramRefreshService)provider;
        await refreshService.RefreshAsync(CancellationToken.None);

        var certificates = await provider.GetCertificatesAsync(CancellationToken.None);

        var certificate = Assert.Single(certificates);
        try
        {
            Assert.Equal(subject, certificate.Subject);
            Assert.Equal(sha256Fingerprint, Convert.ToHexString(certificate.GetCertHash(HashAlgorithmName.SHA256)));
        }
        finally
        {
            certificate.Dispose();
        }
    }

    [Fact]
    public async Task RetriesWhenRateLimited()
    {
        var certificateBytes = CreateTestCertificate(out var sha256Fingerprint, out var sha1Fingerprint, out var subject);

        var csvPayload = BuildCsv(subject, sha1Fingerprint, sha256Fingerprint);

        var crtAttempts = 0;

        using var handler = new StubHttpMessageHandler((request, attempt) =>
        {
            if (request.RequestUri is null)
            {
                throw new InvalidOperationException("Request URI was null");
            }

            if (string.Equals(request.RequestUri.AbsoluteUri, "https://ccadb.my.salesforce-sites.com/microsoft/IncludedCACertificateReportForMSFTCSV", StringComparison.OrdinalIgnoreCase))
            {
                var response = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(csvPayload, Encoding.UTF8)
                };
                response.Content.Headers.ContentType = new MediaTypeHeaderValue("text/csv");
                return response;
            }

            if (string.Equals(request.RequestUri.Host, "crt.sh", StringComparison.OrdinalIgnoreCase))
            {
                if (attempt == 1)
                {
                    var response = new HttpResponseMessage((HttpStatusCode)429);
                    response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromMilliseconds(10));
                    return response;
                }

                crtAttempts = attempt;

                var successResponse = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(certificateBytes)
                };
                successResponse.Content.Headers.ContentType = new MediaTypeHeaderValue("application/pkix-cert");
                return successResponse;
            }

            throw new InvalidOperationException($"Unexpected request to {request.RequestUri}");
        });

        using var httpClient = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(5)
        };
        httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("TrustedRootsVsChrome.Tests/1.0");

        var store = new InMemoryCertificateCacheStore();
    var statusTracker = new CertificateRefreshStatusTracker();
    var provider = new MicrosoftTrustedRootProgramProvider(httpClient, store, NullLogger<MicrosoftTrustedRootProgramProvider>.Instance, statusTracker, statusTracker);

        var refreshService = (IMicrosoftTrustedRootProgramRefreshService)provider;
        await refreshService.RefreshAsync(CancellationToken.None);

        var certificates = await provider.GetCertificatesAsync(CancellationToken.None);

        var certificate = Assert.Single(certificates);
        try
        {
            Assert.Equal(subject, certificate.Subject);
            Assert.Equal(sha256Fingerprint, Convert.ToHexString(certificate.GetCertHash(HashAlgorithmName.SHA256)));
        }
        finally
        {
            certificate.Dispose();
        }

        Assert.True(crtAttempts >= 2, "Expected at least one retry when rate limited");
    }

    private static byte[] CreateTestCertificate(out string sha256Fingerprint, out string sha1Fingerprint, out string subject)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=Trusted Roots Test Root", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));

        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));
        var rawData = certificate.Export(X509ContentType.Cert);

        sha256Fingerprint = Convert.ToHexString(SHA256.HashData(rawData));
        sha1Fingerprint = Convert.ToHexString(SHA1.HashData(rawData));
        subject = certificate.Subject;

        return rawData;
    }

    private static string BuildCsv(string subject, string sha1Fingerprint, string sha256Fingerprint)
    {
        var builder = new StringBuilder();
        builder.AppendLine("\"Microsoft Status\",\"CA Owner\",\"CA Common Name or Certificate Name\",\"Subject\",\"SHA-1 Fingerprint\",\"SHA-256 Fingerprint\",\"Microsoft EKUs\",\"Valid From [GMT]\",\"Valid To [GMT]\",\"Public Key Algorithm\",\"Signature Hash Algorithm\"");
        builder.AppendLine($"\"Included\",\"Test CA\",\"Test Root\",\"{subject}\",\"{sha1Fingerprint}\",\"{sha256Fingerprint}\",\"Server Authentication\",\"2024 Jan 01\",\"2040 Jan 01\",\"RSA 2048 bits\",\"SHA256WithRSA\"");
        return builder.ToString();
    }

    private sealed class StubHttpMessageHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, int, HttpResponseMessage> _responseFactory;
        private readonly ConcurrentDictionary<string, int> _requestCounts = new();

        public StubHttpMessageHandler(Func<HttpRequestMessage, int, HttpResponseMessage> responseFactory)
        {
            _responseFactory = responseFactory;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var key = request.RequestUri?.AbsoluteUri ?? string.Empty;
            var attempt = _requestCounts.AddOrUpdate(key, 1, (_, current) => current + 1);
            var response = _responseFactory(request, attempt);
            return Task.FromResult(response ?? throw new InvalidOperationException("Response factory returned null"));
        }
    }
}

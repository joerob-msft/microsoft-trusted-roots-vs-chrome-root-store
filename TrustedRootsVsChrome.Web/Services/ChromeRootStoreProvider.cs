using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;

namespace TrustedRootsVsChrome.Web.Services;

public sealed class ChromeRootStoreProvider : IChromeRootStoreProvider
{
    private const string CacheKey = "ChromeRootCertificates";
    private static readonly Uri ChromeRootStoreUri = new("https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/root_store.certs?format=TEXT");
    private static readonly Regex PemBlockRegex = new(
        "-----BEGIN CERTIFICATE-----\\s*(?<payload>[A-Za-z0-9+/=\\r\\n]+)-----END CERTIFICATE-----",
        RegexOptions.Compiled);

    private readonly HttpClient _httpClient;
    private readonly IMemoryCache _cache;
    private readonly ILogger<ChromeRootStoreProvider> _logger;

    public ChromeRootStoreProvider(HttpClient httpClient, IMemoryCache cache, ILogger<ChromeRootStoreProvider> logger)
    {
        _httpClient = httpClient;
        _cache = cache;
        _logger = logger;
    }

    public async Task<IReadOnlyCollection<X509Certificate2>> GetCertificatesAsync(CancellationToken cancellationToken)
    {
        return await _cache.GetOrCreateAsync(CacheKey, async entry =>
        {
            entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(12);
            return await DownloadAsync(cancellationToken);
        }) ?? Array.Empty<X509Certificate2>();
    }

    private async Task<IReadOnlyCollection<X509Certificate2>> DownloadAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Downloading Chrome root store from {Uri}", ChromeRootStoreUri);

        using var request = new HttpRequestMessage(HttpMethod.Get, ChromeRootStoreUri);
        using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        response.EnsureSuccessStatusCode();

        var encodedPayload = await response.Content.ReadAsStringAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(encodedPayload))
        {
            throw new InvalidOperationException("Chrome root store payload was empty.");
        }

        // The ?format=TEXT endpoint returns base64-encoded content
        var normalised = encodedPayload.Replace("\n", string.Empty, StringComparison.Ordinal)
                                       .Replace("\r", string.Empty, StringComparison.Ordinal)
                                       .Trim();

        byte[] decodedBytes;
        try
        {
            decodedBytes = Convert.FromBase64String(normalised);
        }
        catch (FormatException ex)
        {
            _logger.LogError(ex, "Failed to decode Chrome root store payload");
            throw new InvalidOperationException("Chrome root store payload was not valid base64.", ex);
        }

        var text = Encoding.UTF8.GetString(decodedBytes);

        var certificates = new List<X509Certificate2>();

        foreach (Match match in PemBlockRegex.Matches(text))
        {
            var pem = new StringBuilder();
            pem.AppendLine("-----BEGIN CERTIFICATE-----");
            pem.AppendLine(match.Groups["payload"].Value.Trim());
            pem.AppendLine("-----END CERTIFICATE-----");

            try
            {
                certificates.Add(X509Certificate2.CreateFromPem(pem.ToString()));
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to parse a certificate from Chrome root store");
            }
        }

        _logger.LogInformation("Parsed {CertificateCount} certificates from Chrome root store", certificates.Count);
        return certificates;
    }
}
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;

namespace TrustedRootsVsChrome.Web.Services;

public sealed class MicrosoftTrustedRootProgramProvider : IMicrosoftTrustedRootProgramProvider
{
    private const string CacheKey = "MicrosoftTrustedRootProgramCertificates";
    private static readonly Uri TrustedRootProgramUri = new("http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authroots.sst");

    private readonly HttpClient _httpClient;
    private readonly IMemoryCache _cache;
    private readonly ILogger<MicrosoftTrustedRootProgramProvider> _logger;

    public MicrosoftTrustedRootProgramProvider(HttpClient httpClient, IMemoryCache cache, ILogger<MicrosoftTrustedRootProgramProvider> logger)
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
        _logger.LogInformation("Downloading Microsoft Trusted Root Program list from {Uri}", TrustedRootProgramUri);

        using var response = await _httpClient.GetAsync(TrustedRootProgramUri, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        response.EnsureSuccessStatusCode();

        var payload = await response.Content.ReadAsByteArrayAsync(cancellationToken);

        var collection = new X509Certificate2Collection();

        try
        {
            collection.Import(payload);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to import Microsoft Trusted Root Program certificates");
            throw new InvalidOperationException("Microsoft Trusted Root Program payload could not be parsed.", ex);
        }

        var certificates = collection
            .Cast<X509Certificate2>()
            .Select(cert => new X509Certificate2(cert))
            .ToArray();

        _logger.LogInformation("Parsed {Count} certificates from Microsoft Trusted Root Program", certificates.Length);
        return certificates;
    }
}
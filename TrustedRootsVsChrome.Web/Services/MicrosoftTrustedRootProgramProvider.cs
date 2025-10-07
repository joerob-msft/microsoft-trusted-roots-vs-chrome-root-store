using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.VisualBasic.FileIO;

namespace TrustedRootsVsChrome.Web.Services;

public sealed class MicrosoftTrustedRootProgramProvider : IMicrosoftTrustedRootProgramProvider, IMicrosoftTrustedRootProgramRefreshService
{
    private const string CacheKey = "MicrosoftTrustedRootProgramCertificates";
    private const int CertificateDownloadConcurrency = 4;
    private const int MaxCertificateDownloadAttempts = 6;

    private static readonly Uri ReportCsvUri = new("https://ccadb.my.salesforce-sites.com/microsoft/IncludedCACertificateReportForMSFTCSV");

    private readonly HttpClient _httpClient;
    private readonly ICertificateCacheStore _store;
    private readonly ILogger<MicrosoftTrustedRootProgramProvider> _logger;
    private readonly ICertificateRefreshStatusProvider _statusProvider;
    private readonly ICertificateRefreshStatusUpdater _statusUpdater;
    private int _refreshRequested;

    public MicrosoftTrustedRootProgramProvider(
        HttpClient httpClient,
        ICertificateCacheStore store,
        ILogger<MicrosoftTrustedRootProgramProvider> logger,
        ICertificateRefreshStatusProvider statusProvider,
        ICertificateRefreshStatusUpdater statusUpdater)
    {
        _httpClient = httpClient;
        _store = store;
        _logger = logger;
        _statusProvider = statusProvider;
        _statusUpdater = statusUpdater;
    }

    public async Task<IReadOnlyCollection<X509Certificate2>> GetCertificatesAsync(CancellationToken cancellationToken)
    {
        var cached = await _store.GetAsync(CacheKey, cancellationToken).ConfigureAwait(false);
        if (cached.Count > 0)
        {
            return cached;
        }

        _logger.LogInformation("Microsoft Trusted Root Program cache is empty; returning no certificates while a refresh is scheduled.");

        var status = _statusProvider.GetStatus();
        if (!status.IsRefreshing)
        {
            EnsureRefreshScheduled();
        }

        return Array.Empty<X509Certificate2>();
    }

    public async Task RefreshAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Refreshing Microsoft Trusted Root Program certificate cache");
        _statusUpdater.BeginRefresh();

        try
        {
            var certificates = await DownloadAsync(cancellationToken).ConfigureAwait(false);
            var payloads = new List<byte[]>(certificates.Count);

            try
            {
                foreach (var certificate in certificates)
                {
                    payloads.Add(certificate.Export(X509ContentType.Cert));
                }

                await _store.SaveAsync(CacheKey, payloads, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                foreach (var certificate in certificates)
                {
                    certificate.Dispose();
                }
            }

            _statusUpdater.CompleteSuccess();
            _logger.LogInformation("Persisted {CertificateCount} Microsoft Trusted Root Program certificates", payloads.Count);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _statusUpdater.CompleteFailure(ex.Message);
            throw;
        }
    }

    private async Task<IReadOnlyCollection<X509Certificate2>> DownloadAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Downloading Microsoft Trusted Root Program report from {Uri}", ReportCsvUri);

        var csv = await DownloadReportCsvAsync(cancellationToken).ConfigureAwait(false);

        if (string.IsNullOrWhiteSpace(csv))
        {
            _logger.LogError("Microsoft Trusted Root Program report returned no content");
            throw new InvalidOperationException("Microsoft Trusted Root Program report could not be retrieved.");
        }

        var entries = ParseReport(csv);

        if (entries.Count == 0)
        {
            _logger.LogError("Microsoft Trusted Root Program report did not contain any active certificates");
            throw new InvalidOperationException("Microsoft Trusted Root Program report did not contain any active certificates.");
        }

        var distinctFingerprints = entries
            .Select(static entry => entry.Sha256)
            .Where(static fingerprint => !string.IsNullOrWhiteSpace(fingerprint))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        _statusUpdater?.SetTotalCertificates(distinctFingerprints.Count);

        var certificates = await DownloadCertificatesAsync(distinctFingerprints, cancellationToken).ConfigureAwait(false);

        if (certificates.Count == 0)
        {
            _logger.LogError("Microsoft Trusted Root Program report produced {Count} active entries but none could be downloaded", entries.Count);
            throw new InvalidOperationException("Microsoft Trusted Root Program certificates could not be downloaded.");
        }

        _logger.LogInformation("Downloaded {CertificateCount} certificates from Microsoft Trusted Root Program report", certificates.Count);
        return certificates;
    }

    private async Task<string> DownloadReportCsvAsync(CancellationToken cancellationToken)
    {
        using var response = await _httpClient.GetAsync(ReportCsvUri, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);

        _logger.LogInformation("Received {StatusCode} from {Uri}", response.StatusCode, ReportCsvUri);

        response.EnsureSuccessStatusCode();

        return await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
    }

    private IReadOnlyList<CcAdbCertificateEntry> ParseReport(string csv)
    {
        if (string.IsNullOrWhiteSpace(csv))
        {
            _logger.LogWarning("Microsoft Trusted Root Program CSV report did not contain any data");
            return Array.Empty<CcAdbCertificateEntry>();
        }

        using var reader = new StringReader(csv);
        using var parser = new TextFieldParser(reader)
        {
            TextFieldType = FieldType.Delimited,
            HasFieldsEnclosedInQuotes = true,
            TrimWhiteSpace = false
        };
        parser.SetDelimiters(",");

        if (parser.EndOfData)
        {
            _logger.LogWarning("Microsoft Trusted Root Program CSV report was empty");
            return Array.Empty<CcAdbCertificateEntry>();
        }

        var headerFields = parser.ReadFields();
        if (headerFields is null || headerFields.Length == 0)
        {
            _logger.LogWarning("Microsoft Trusted Root Program CSV report did not contain headers");
            return Array.Empty<CcAdbCertificateEntry>();
        }

        var headerLookup = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < headerFields.Length; i++)
        {
            var header = headerFields[i]?.Trim();
            if (string.IsNullOrEmpty(header) || headerLookup.ContainsKey(header))
            {
                continue;
            }

            headerLookup[header] = i;
        }

        if (!TryGetIndex(headerLookup, "Microsoft Status", out var statusIndex) ||
            !TryGetIndex(headerLookup, "SHA-256 Fingerprint", out var sha256Index) ||
            !TryGetIndex(headerLookup, "Valid From [GMT]", out var validFromIndex) ||
            !TryGetIndex(headerLookup, "Valid To [GMT]", out var validToIndex))
        {
            _logger.LogError("Microsoft Trusted Root Program CSV report is missing required columns");
            return Array.Empty<CcAdbCertificateEntry>();
        }

        TryGetIndex(headerLookup, "SHA-1 Fingerprint", out var sha1Index);

        var now = DateTimeOffset.UtcNow;
        var entries = new List<CcAdbCertificateEntry>();

        while (!parser.EndOfData)
        {
            string[]? fields;
            try
            {
                fields = parser.ReadFields();
            }
            catch (MalformedLineException ex)
            {
                _logger.LogWarning(ex, "Skipping malformed CSV line {LineNumber}", parser.LineNumber);
                continue;
            }

            if (fields is null || fields.Length == 0)
            {
                continue;
            }

            var status = GetField(fields, statusIndex);
            if (!IsActiveStatus(status))
            {
                continue;
            }

            var sha256Raw = GetField(fields, sha256Index);
            if (string.IsNullOrWhiteSpace(sha256Raw))
            {
                continue;
            }

            var sha256 = NormalizeFingerprint(sha256Raw);

            string? sha1 = null;
            if (sha1Index >= 0)
            {
                var sha1Raw = GetField(fields, sha1Index);
                if (!string.IsNullOrWhiteSpace(sha1Raw))
                {
                    sha1 = NormalizeFingerprint(sha1Raw);
                }
            }

            var notBefore = ParseDate(GetField(fields, validFromIndex));
            var notAfter = ParseDate(GetField(fields, validToIndex));

            var entry = new CcAdbCertificateEntry(status, sha256, sha1, notBefore, notAfter);

            if (!entry.IsActive(now))
            {
                continue;
            }

            entries.Add(entry);
        }

        _logger.LogInformation("Parsed {ActiveCount} active certificates from Microsoft Trusted Root Program report", entries.Count);

        return entries;
    }

    private static bool IsActiveStatus(string status)
        => !string.IsNullOrWhiteSpace(status) && status.StartsWith("Included", StringComparison.OrdinalIgnoreCase);

    private static bool TryGetIndex(IReadOnlyDictionary<string, int> lookup, string name, out int index)
    {
        if (lookup.TryGetValue(name, out index))
        {
            return true;
        }

        index = -1;
        return false;
    }

    private static string GetField(IReadOnlyList<string> fields, int index)
    {
        if (index < 0 || index >= fields.Count)
        {
            return string.Empty;
        }

        return fields[index]?.Trim() ?? string.Empty;
    }

    private static DateTimeOffset? ParseDate(string? text)
    {
        if (string.IsNullOrWhiteSpace(text) || text.Equals("N/A", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var formats = new[]
        {
            "yyyy MMM dd",
            "yyyy MMM d",
            "yyyy MMM dd HH:mm:ss",
            "yyyy MMM d HH:mm:ss",
            "yyyy-MM-dd",
            "M/d/yyyy",
            "M/d/yyyy h:mm tt"
        };

        if (DateTimeOffset.TryParseExact(
                text,
                formats,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal | DateTimeStyles.AllowWhiteSpaces,
                out var parsed))
        {
            return parsed;
        }

        if (DateTimeOffset.TryParse(
                text,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal | DateTimeStyles.AllowWhiteSpaces,
                out parsed))
        {
            return parsed;
        }

        return null;
    }

    private async Task<IReadOnlyCollection<X509Certificate2>> DownloadCertificatesAsync(IReadOnlyList<string> fingerprints, CancellationToken cancellationToken)
    {
        if (fingerprints.Count == 0)
        {
            return Array.Empty<X509Certificate2>();
        }

        var certificates = new ConcurrentBag<X509Certificate2>();
        var processedCount = 0;

        await Parallel.ForEachAsync(fingerprints, new ParallelOptions
        {
            MaxDegreeOfParallelism = CertificateDownloadConcurrency,
            CancellationToken = cancellationToken
        }, async (fingerprint, ct) =>
        {
            var certificate = await DownloadCertificateAsync(fingerprint, ct).ConfigureAwait(false);
            if (certificate is not null)
            {
                certificates.Add(certificate);
            }

            var processed = Interlocked.Increment(ref processedCount);
            _statusUpdater.ReportProgress(processed);
        }).ConfigureAwait(false);

        return certificates.ToArray();
    }

    private void EnsureRefreshScheduled()
    {
        if (Interlocked.CompareExchange(ref _refreshRequested, 1, 0) != 0)
        {
            return;
        }

        _ = Task.Run(async () =>
        {
            try
            {
                await RefreshAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Ignore cancellation when triggered during shutdown.
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Background refresh triggered from GetCertificatesAsync failed");
            }
            finally
            {
                Interlocked.Exchange(ref _refreshRequested, 0);
            }
        }, CancellationToken.None);
    }

    private async Task<X509Certificate2?> DownloadCertificateAsync(string fingerprint, CancellationToken cancellationToken)
    {
        var requestUri = new Uri($"https://crt.sh/?d={fingerprint}");

        for (var attempt = 1; attempt <= MaxCertificateDownloadAttempts; attempt++)
        {
            try
            {
                using var response = await _httpClient.GetAsync(requestUri, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);

                if (response.IsSuccessStatusCode)
                {
                    var payload = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);

                    if (payload.Length == 0)
                    {
                        _logger.LogWarning("Certificate {Fingerprint} returned an empty payload", fingerprint);
                        return null;
                    }

                    try
                    {
                        return new X509Certificate2(payload);
                    }
                    catch (CryptographicException ex)
                    {
                        _logger.LogWarning(ex, "Failed to parse certificate {Fingerprint}", fingerprint);
                        return null;
                    }
                }

                if (IsRetryableStatus(response.StatusCode))
                {
                    var delay = GetRetryDelay(response.Headers.RetryAfter, attempt);
                    _logger.LogWarning("Received status code {StatusCode} when fetching certificate {Fingerprint}. Attempt {Attempt} of {MaxAttempts}. Retrying in {Delay}.", response.StatusCode, fingerprint, attempt, MaxCertificateDownloadAttempts, delay);

                    await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                    continue;
                }

                _logger.LogWarning("Received status code {StatusCode} when fetching certificate {Fingerprint} on attempt {Attempt}", response.StatusCode, fingerprint, attempt);
                return null;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (HttpRequestException ex)
            {
                if (attempt >= MaxCertificateDownloadAttempts)
                {
                    _logger.LogWarning(ex, "Failed to download certificate {Fingerprint} after {Attempts} attempts", fingerprint, attempt);
                    return null;
                }

                var delay = GetRetryDelay(null, attempt);
                _logger.LogWarning(ex, "Attempt {Attempt} of {MaxAttempts} failed to download certificate {Fingerprint}. Retrying in {Delay}.", attempt, MaxCertificateDownloadAttempts, fingerprint, delay);

                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            }
        }

        _logger.LogWarning("Exceeded retry limit when downloading certificate {Fingerprint}", fingerprint);
        return null;
    }

    private static bool IsRetryableStatus(HttpStatusCode statusCode)
        => statusCode == (HttpStatusCode)429 || (int)statusCode >= 500;

    private static TimeSpan GetRetryDelay(RetryConditionHeaderValue? retryAfter, int attempt)
    {
        if (retryAfter is not null)
        {
            if (retryAfter.Delta is TimeSpan delta && delta > TimeSpan.Zero)
            {
                return ApplyJitter(delta);
            }

            if (retryAfter.Date is DateTimeOffset date)
            {
                var deltaFromDate = date - DateTimeOffset.UtcNow;
                if (deltaFromDate > TimeSpan.Zero)
                {
                    return ApplyJitter(deltaFromDate);
                }
            }
        }

        var exponentialMilliseconds = Math.Min(5000, 200 * Math.Pow(2, attempt - 1));
        return ApplyJitter(TimeSpan.FromMilliseconds(exponentialMilliseconds));
    }

    private static TimeSpan ApplyJitter(TimeSpan baseDelay)
    {
        var jitterMilliseconds = Random.Shared.Next(100, 300);
        var delay = baseDelay + TimeSpan.FromMilliseconds(jitterMilliseconds);
        return delay > TimeSpan.Zero ? delay : TimeSpan.FromMilliseconds(jitterMilliseconds);
    }

    private static string NormalizeFingerprint(string fingerprint)
    {
        var span = fingerprint.AsSpan();
        Span<char> buffer = stackalloc char[fingerprint.Length];
        var index = 0;

        foreach (var ch in span)
        {
            if (char.IsLetterOrDigit(ch))
            {
                buffer[index++] = char.ToUpperInvariant(ch);
            }
        }

        return new string(buffer[..index]);
    }

    private sealed record CcAdbCertificateEntry(string Status, string Sha256, string? Sha1, DateTimeOffset? NotBefore, DateTimeOffset? NotAfter)
    {
        public bool IsActive(DateTimeOffset now)
        {
            if (string.IsNullOrWhiteSpace(Sha256))
            {
                return false;
            }

            if (NotBefore.HasValue && NotBefore.Value > now)
            {
                return false;
            }

            if (NotAfter.HasValue && NotAfter.Value < now)
            {
                return false;
            }

            return Status.StartsWith("Included", StringComparison.OrdinalIgnoreCase);
        }
    }
}
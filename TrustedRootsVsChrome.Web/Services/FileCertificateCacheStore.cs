using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;

namespace TrustedRootsVsChrome.Web.Services;

public sealed class FileCertificateCacheStore : ICertificateCacheStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false
    };

    private readonly string _basePath;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public FileCertificateCacheStore(IHostEnvironment hostEnvironment)
    {
        _basePath = Path.Combine(hostEnvironment.ContentRootPath, "App_Data", "certificate-cache");
        Directory.CreateDirectory(_basePath);
    }

    public async Task SaveAsync(string key, IReadOnlyCollection<byte[]> certificates, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        var document = new CertificateCacheDocument
        {
            LastUpdatedUtc = DateTimeOffset.UtcNow,
            Certificates = certificates.Select(static payload => Convert.ToBase64String(payload)).ToList()
        };

        var path = GetPath(key);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var json = JsonSerializer.Serialize(document, SerializerOptions);
            await File.WriteAllTextAsync(path, json, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyCollection<X509Certificate2>> GetAsync(string key, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        var path = GetPath(key);
        if (!File.Exists(path))
        {
            return Array.Empty<X509Certificate2>();
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var stream = File.OpenRead(path);
            var document = await JsonSerializer.DeserializeAsync<CertificateCacheDocument>(stream, SerializerOptions, cancellationToken).ConfigureAwait(false);
            if (document is null || document.Certificates.Count == 0)
            {
                return Array.Empty<X509Certificate2>();
            }

            var certificates = new List<X509Certificate2>(document.Certificates.Count);
            foreach (var base64 in document.Certificates)
            {
                if (string.IsNullOrWhiteSpace(base64))
                {
                    continue;
                }

                try
                {
                    var bytes = Convert.FromBase64String(base64);
                    certificates.Add(new X509Certificate2(bytes));
                }
                catch
                {
                    // Skip malformed entries; background refresh will replace them.
                }
            }

            return certificates;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<DateTimeOffset?> GetLastUpdatedAsync(string key, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        var path = GetPath(key);
        if (!File.Exists(path))
        {
            return null;
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var stream = File.OpenRead(path);
            var document = await JsonSerializer.DeserializeAsync<CertificateCacheDocument>(stream, SerializerOptions, cancellationToken).ConfigureAwait(false);
            return document?.LastUpdatedUtc;
        }
        finally
        {
            _gate.Release();
        }
    }

    private string GetPath(string key)
    {
        var fileName = key.Replace('/', '_').Replace('\\', '_');
        return Path.Combine(_basePath, $"{fileName}.json");
    }

    private sealed class CertificateCacheDocument
    {
        public DateTimeOffset LastUpdatedUtc { get; set; }

        public List<string> Certificates { get; set; } = new();
    }
}
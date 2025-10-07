using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using TrustedRootsVsChrome.Web.Services;

namespace TrustedRootsVsChrome.Tests;

internal sealed class InMemoryCertificateCacheStore : ICertificateCacheStore
{
    private readonly ConcurrentDictionary<string, CacheEntry> _entries = new(StringComparer.OrdinalIgnoreCase);

    public Task SaveAsync(string key, IReadOnlyCollection<byte[]> certificates, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        var snapshot = certificates.Select(static bytes => bytes.ToArray()).ToList();
        var entry = new CacheEntry(DateTimeOffset.UtcNow, snapshot);
        _entries[key] = entry;

        return Task.CompletedTask;
    }

    public Task<IReadOnlyCollection<X509Certificate2>> GetAsync(string key, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        if (!_entries.TryGetValue(key, out var entry) || entry.Certificates.Count == 0)
        {
            return Task.FromResult<IReadOnlyCollection<X509Certificate2>>(Array.Empty<X509Certificate2>());
        }

        var materialised = entry.Certificates
            .Select(static bytes => new X509Certificate2(bytes))
            .ToList();

        return Task.FromResult<IReadOnlyCollection<X509Certificate2>>(materialised);
    }

    public Task<DateTimeOffset?> GetLastUpdatedAsync(string key, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        if (_entries.TryGetValue(key, out var entry))
        {
            return Task.FromResult<DateTimeOffset?>(entry.LastUpdatedUtc);
        }

        return Task.FromResult<DateTimeOffset?>(null);
    }

    private sealed record CacheEntry(DateTimeOffset LastUpdatedUtc, IReadOnlyCollection<byte[]> Certificates);
}
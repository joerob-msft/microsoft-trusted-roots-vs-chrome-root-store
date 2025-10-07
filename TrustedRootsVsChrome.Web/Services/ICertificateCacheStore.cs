using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace TrustedRootsVsChrome.Web.Services;

public interface ICertificateCacheStore
{
    Task SaveAsync(string key, IReadOnlyCollection<byte[]> certificates, CancellationToken cancellationToken);

    Task<IReadOnlyCollection<X509Certificate2>> GetAsync(string key, CancellationToken cancellationToken);

    Task<DateTimeOffset?> GetLastUpdatedAsync(string key, CancellationToken cancellationToken);
}
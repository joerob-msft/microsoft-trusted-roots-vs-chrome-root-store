using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace TrustedRootsVsChrome.Web.Services;

public interface IChromeRootStoreProvider
{
    Task<IReadOnlyCollection<X509Certificate2>> GetCertificatesAsync(CancellationToken cancellationToken);
}
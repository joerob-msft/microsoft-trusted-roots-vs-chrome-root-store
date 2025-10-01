using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace TrustedRootsVsChrome.Web.Services;

public interface IWindowsTrustedRootProvider
{
    IReadOnlyCollection<X509Certificate2> GetTrustedRoots();
}
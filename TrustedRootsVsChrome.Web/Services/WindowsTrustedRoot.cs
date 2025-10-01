using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace TrustedRootsVsChrome.Web.Services;

public sealed record WindowsTrustedRoot(
    X509Certificate2 Certificate,
    IReadOnlyCollection<string> Sources);

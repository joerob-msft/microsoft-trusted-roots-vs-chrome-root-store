using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;

namespace TrustedRootsVsChrome.Web.Services;

public sealed class WindowsTrustedRootProvider : IWindowsTrustedRootProvider
{
    private readonly ILogger<WindowsTrustedRootProvider> _logger;

    public WindowsTrustedRootProvider(ILogger<WindowsTrustedRootProvider> logger)
    {
        _logger = logger;
    }

    public IReadOnlyCollection<X509Certificate2> GetTrustedRoots()
    {
        var certificates = new Dictionary<string, X509Certificate2>(StringComparer.OrdinalIgnoreCase);

        foreach (var location in new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine })
        {
            try
            {
                using var store = new X509Store(StoreName.Root, location);
                store.Open(OpenFlags.ReadOnly);

                foreach (var certificate in store.Certificates)
                {
                    if (!certificates.ContainsKey(certificate.Thumbprint))
                    {
                        certificates.Add(certificate.Thumbprint, certificate);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Unable to read certificates from {Location} root store", location);
            }
        }

        _logger.LogInformation("Collected {Count} unique trusted root certificates from Windows stores", certificates.Count);
        return certificates.Values;
    }
}
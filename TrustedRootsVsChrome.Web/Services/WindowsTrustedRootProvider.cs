using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;

namespace TrustedRootsVsChrome.Web.Services;

public sealed class WindowsTrustedRootProvider : IWindowsTrustedRootProvider
{
    private readonly ILogger<WindowsTrustedRootProvider> _logger;

    private static readonly OpenFlags StoreOpenFlags = OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly;

    private static readonly IReadOnlyList<StoreDescriptor> StoreDescriptors = new[]
    {
        new StoreDescriptor("Current User / Trusted Root", () => new X509Store(StoreName.Root, StoreLocation.CurrentUser)),
        new StoreDescriptor("Current User / Third-Party Root", () => new X509Store(StoreName.AuthRoot, StoreLocation.CurrentUser)),
        new StoreDescriptor("Local Machine / Trusted Root", () => new X509Store(StoreName.Root, StoreLocation.LocalMachine)),
        new StoreDescriptor("Local Machine / Third-Party Root", () => new X509Store(StoreName.AuthRoot, StoreLocation.LocalMachine)),
        new StoreDescriptor("Local Machine / Group Policy Root", () => new X509Store("Root\\GroupPolicy", StoreLocation.LocalMachine)),
        new StoreDescriptor("Local Machine / Enterprise Root", () => new X509Store("Root\\Enterprise", StoreLocation.LocalMachine))
    };

    public WindowsTrustedRootProvider(ILogger<WindowsTrustedRootProvider> logger)
    {
        _logger = logger;
    }

    public IReadOnlyCollection<WindowsTrustedRoot> GetTrustedRoots()
    {
        var certificates = new Dictionary<string, RootAccumulator>(StringComparer.OrdinalIgnoreCase);

        foreach (var descriptor in StoreDescriptors)
        {
            try
            {
                using var store = descriptor.CreateStore();
                store.Open(StoreOpenFlags);

                foreach (var certificate in store.Certificates)
                {
                    if (string.IsNullOrWhiteSpace(certificate.Thumbprint))
                    {
                        continue;
                    }

                    if (!certificates.TryGetValue(certificate.Thumbprint, out var accumulator))
                    {
                        accumulator = new RootAccumulator(new X509Certificate2(certificate));
                        certificates.Add(certificate.Thumbprint, accumulator);
                    }

                    accumulator.AddSource(descriptor.DisplayName);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Unable to read certificates from {Store}", descriptor.DisplayName);
            }
        }

        var results = certificates.Values
            .Select(accumulator => accumulator.ToWindowsTrustedRoot())
            .ToArray();

        _logger.LogInformation("Collected {Count} unique trusted root certificates from Windows stores", results.Length);
        return results;
    }

    private sealed record StoreDescriptor(string DisplayName, Func<X509Store> CreateStore);

    private sealed class RootAccumulator
    {
        private readonly SortedSet<string> _sources = new(StringComparer.OrdinalIgnoreCase);

        public RootAccumulator(X509Certificate2 certificate)
        {
            Certificate = certificate;
        }

        public X509Certificate2 Certificate { get; }

        public void AddSource(string source)
            => _sources.Add(source);

        public WindowsTrustedRoot ToWindowsTrustedRoot()
            => new(Certificate, _sources.ToArray());
    }
}
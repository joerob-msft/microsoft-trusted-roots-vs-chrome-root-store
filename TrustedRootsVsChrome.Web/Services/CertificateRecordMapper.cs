using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using TrustedRootsVsChrome.Web.Models;

namespace TrustedRootsVsChrome.Web.Services;

internal static class CertificateRecordMapper
{
    private static readonly IReadOnlyCollection<string> MicrosoftProgramSource = new[] { "Microsoft Trusted Root Program" };
    private static readonly IReadOnlyCollection<string> ChromeRootStoreSource = new[] { "Chrome Root Store" };

    public static CertificateRecord FromMicrosoftTrustedRootProgram(X509Certificate2 certificate)
        => ToRecord(certificate, MicrosoftProgramSource);

    public static CertificateRecord FromChromeRootStore(X509Certificate2 certificate)
        => ToRecord(certificate, ChromeRootStoreSource);

    private static CertificateRecord ToRecord(X509Certificate2 certificate, IReadOnlyCollection<string> sources)
        => new(
            certificate.Subject,
            certificate.Issuer,
            certificate.Thumbprint,
            certificate.NotBefore.ToUniversalTime(),
            certificate.NotAfter.ToUniversalTime(),
            certificate.Version,
            sources,
            string.IsNullOrWhiteSpace(certificate.FriendlyName) ? null : certificate.FriendlyName);
}
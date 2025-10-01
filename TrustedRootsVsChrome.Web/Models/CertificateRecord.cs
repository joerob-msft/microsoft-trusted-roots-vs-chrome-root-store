using System;

namespace TrustedRootsVsChrome.Web.Models;

public sealed record CertificateRecord(
    string Subject,
    string Issuer,
    string Thumbprint,
    DateTime NotBeforeUtc,
    DateTime NotAfterUtc,
    int Version,
    string? FriendlyName = null);
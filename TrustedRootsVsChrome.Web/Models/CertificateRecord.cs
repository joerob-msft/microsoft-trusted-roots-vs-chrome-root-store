using System;
using System.Collections.Generic;

namespace TrustedRootsVsChrome.Web.Models;

public sealed record CertificateRecord(
    string Subject,
    string Issuer,
    string Thumbprint,
    DateTime NotBeforeUtc,
    DateTime NotAfterUtc,
    int Version,
    IReadOnlyCollection<string> Sources,
    string? FriendlyName = null);
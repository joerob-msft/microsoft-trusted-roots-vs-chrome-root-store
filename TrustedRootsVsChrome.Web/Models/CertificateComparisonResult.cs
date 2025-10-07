using System;
using System.Collections.Generic;

namespace TrustedRootsVsChrome.Web.Models;

public sealed class CertificateComparisonResult
{
    public required IReadOnlyList<CertificateRecord> MissingInChrome { get; init; }

    public DateTime RetrievedAtUtc { get; init; }

    public string? ErrorMessage { get; init; }
}
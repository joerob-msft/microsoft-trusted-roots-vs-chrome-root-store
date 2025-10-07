using System;

namespace TrustedRootsVsChrome.Web.Models;

public sealed record CertificateRefreshStatus
{
    public static CertificateRefreshStatus Empty { get; } = new();

    public bool IsRefreshing { get; init; }

    public int TotalCertificates { get; init; }

    public int ProcessedCertificates { get; init; }

    public DateTimeOffset? LastAttemptUtc { get; init; }

    public DateTimeOffset? LastSuccessUtc { get; init; }

    public string? ErrorMessage { get; init; }

    public double ProgressFraction
    {
        get
        {
            if (TotalCertificates <= 0)
            {
                return 0d;
            }

            var fraction = (double)ProcessedCertificates / TotalCertificates;
            return Math.Clamp(fraction, 0d, 1d);
        }
    }

    public int ProgressPercentage => TotalCertificates <= 0
        ? 0
        : (int)Math.Clamp(Math.Round(ProgressFraction * 100, MidpointRounding.AwayFromZero), 0, 100);
}
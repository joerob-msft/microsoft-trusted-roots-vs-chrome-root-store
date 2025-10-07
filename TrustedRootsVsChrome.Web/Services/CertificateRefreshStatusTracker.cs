using System;
using TrustedRootsVsChrome.Web.Models;

namespace TrustedRootsVsChrome.Web.Services;

public sealed class CertificateRefreshStatusTracker : ICertificateRefreshStatusProvider, ICertificateRefreshStatusUpdater
{
    private readonly object _sync = new();
    private CertificateRefreshStatus _status = CertificateRefreshStatus.Empty;

    public CertificateRefreshStatus GetStatus()
    {
        lock (_sync)
        {
            return _status;
        }
    }

    public void BeginRefresh()
    {
        lock (_sync)
        {
            _status = _status with
            {
                IsRefreshing = true,
                TotalCertificates = 0,
                ProcessedCertificates = 0,
                LastAttemptUtc = DateTimeOffset.UtcNow,
                ErrorMessage = null
            };
        }
    }

    public void SetTotalCertificates(int total)
    {
        lock (_sync)
        {
            if (!_status.IsRefreshing)
            {
                return;
            }

            _status = _status with { TotalCertificates = Math.Max(0, total) };
        }
    }

    public void ReportProgress(int processed)
    {
        lock (_sync)
        {
            if (!_status.IsRefreshing)
            {
                return;
            }

            var capped = processed;
            if (_status.TotalCertificates > 0)
            {
                capped = Math.Min(processed, _status.TotalCertificates);
            }

            _status = _status with { ProcessedCertificates = Math.Max(0, capped) };
        }
    }

    public void CompleteSuccess()
    {
        lock (_sync)
        {
            var total = _status.TotalCertificates > 0 ? _status.TotalCertificates : _status.ProcessedCertificates;

            _status = _status with
            {
                IsRefreshing = false,
                TotalCertificates = total,
                ProcessedCertificates = total,
                LastSuccessUtc = DateTimeOffset.UtcNow,
                ErrorMessage = null
            };
        }
    }

    public void CompleteFailure(string errorMessage)
    {
        lock (_sync)
        {
            _status = _status with
            {
                IsRefreshing = false,
                ErrorMessage = errorMessage
            };
        }
    }
}
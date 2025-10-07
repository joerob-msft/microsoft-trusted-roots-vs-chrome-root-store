using System;
using System.Threading;
using System.Threading.Tasks;
using TrustedRootsVsChrome.Web.Models;
using TrustedRootsVsChrome.Web.Services;
using Xunit;

namespace TrustedRootsVsChrome.Tests;

public sealed class CertificateRefreshStatusTrackerTests
{
    [Fact]
    public void ReportsProgressLifecycle()
    {
        var tracker = new CertificateRefreshStatusTracker();

        var initial = tracker.GetStatus();
        Assert.False(initial.IsRefreshing);
        Assert.Equal(0, initial.TotalCertificates);

        tracker.BeginRefresh();
        tracker.SetTotalCertificates(10);

        Parallel.For(0, 5, _ => tracker.ReportProgress(1));
        tracker.ReportProgress(7);

        var during = tracker.GetStatus();
        Assert.True(during.IsRefreshing);
        Assert.Equal(10, during.TotalCertificates);
        Assert.InRange(during.ProcessedCertificates, 1, 10);
        Assert.NotNull(during.LastAttemptUtc);

        tracker.CompleteSuccess();

        var complete = tracker.GetStatus();
        Assert.False(complete.IsRefreshing);
        Assert.Equal(10, complete.TotalCertificates);
        Assert.Equal(10, complete.ProcessedCertificates);
        Assert.NotNull(complete.LastSuccessUtc);
        Assert.Null(complete.ErrorMessage);
    }

    [Fact]
    public void RecordsErrorOnFailure()
    {
        var tracker = new CertificateRefreshStatusTracker();

        tracker.BeginRefresh();
        tracker.CompleteFailure("network error");

        var status = tracker.GetStatus();
        Assert.False(status.IsRefreshing);
        Assert.Equal("network error", status.ErrorMessage);
    }
}

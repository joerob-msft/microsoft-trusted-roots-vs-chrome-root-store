namespace TrustedRootsVsChrome.Web.Services;

public interface ICertificateRefreshStatusUpdater
{
    void BeginRefresh();

    void SetTotalCertificates(int total);

    void ReportProgress(int processed);

    void CompleteSuccess();

    void CompleteFailure(string errorMessage);
}
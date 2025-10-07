using TrustedRootsVsChrome.Web.Models;

namespace TrustedRootsVsChrome.Web.Services;

public interface ICertificateRefreshStatusProvider
{
    CertificateRefreshStatus GetStatus();
}
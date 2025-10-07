using System.Threading;
using System.Threading.Tasks;

namespace TrustedRootsVsChrome.Web.Services;

public interface IMicrosoftTrustedRootProgramRefreshService
{
    Task RefreshAsync(CancellationToken cancellationToken);
}
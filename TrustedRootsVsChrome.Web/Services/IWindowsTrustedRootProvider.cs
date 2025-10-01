using System.Collections.Generic;

namespace TrustedRootsVsChrome.Web.Services;

public interface IWindowsTrustedRootProvider
{
    IReadOnlyCollection<WindowsTrustedRoot> GetTrustedRoots();
}
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.RazorPages;
using TrustedRootsVsChrome.Web.Models;
using TrustedRootsVsChrome.Web.Services;

namespace TrustedRootsVsChrome.Web.Pages;

public class ChromeCertificatesModel : PageModel
{
    private readonly IChromeRootStoreProvider _chromeRootStoreProvider;
    private readonly IMicrosoftTrustedRootProgramProvider _microsoftTrustedRootProgramProvider;

    public IReadOnlyList<StoreCertificateRecord> Certificates { get; private set; } = Array.Empty<StoreCertificateRecord>();

    public DateTime RetrievedAtUtc { get; private set; }

    public int ProgramOverlapCount { get; private set; }

    public ChromeCertificatesModel(
        IChromeRootStoreProvider chromeRootStoreProvider,
        IMicrosoftTrustedRootProgramProvider microsoftTrustedRootProgramProvider)
    {
        _chromeRootStoreProvider = chromeRootStoreProvider;
        _microsoftTrustedRootProgramProvider = microsoftTrustedRootProgramProvider;
    }

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        var chromeTask = _chromeRootStoreProvider.GetCertificatesAsync(cancellationToken);
        var microsoftTask = _microsoftTrustedRootProgramProvider.GetCertificatesAsync(cancellationToken);

        var chromeRoots = await chromeTask;
        var microsoftRoots = await microsoftTask;

        var microsoftThumbprints = new HashSet<string>(microsoftRoots.Select(cert => cert.Thumbprint), StringComparer.OrdinalIgnoreCase);

        var records = new List<StoreCertificateRecord>(chromeRoots.Count);

        foreach (var certificate in chromeRoots)
        {
            var record = CertificateRecordMapper.FromChromeRootStore(certificate);
            var presentInProgram = microsoftThumbprints.Contains(certificate.Thumbprint);

            if (presentInProgram)
            {
                ProgramOverlapCount++;
            }

            records.Add(new StoreCertificateRecord(record, presentInProgram));
        }

        Certificates = records
            .OrderBy(r => r.Certificate.Subject, StringComparer.OrdinalIgnoreCase)
            .ThenBy(r => r.Certificate.Thumbprint, StringComparer.OrdinalIgnoreCase)
            .ToList();

        RetrievedAtUtc = DateTime.UtcNow;
    }
}
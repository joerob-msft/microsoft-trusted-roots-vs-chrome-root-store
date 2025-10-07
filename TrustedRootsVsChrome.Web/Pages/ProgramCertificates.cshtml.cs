using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.RazorPages;
using TrustedRootsVsChrome.Web.Models;
using TrustedRootsVsChrome.Web.Services;

namespace TrustedRootsVsChrome.Web.Pages;

public class ProgramCertificatesModel : PageModel
{
    private readonly IMicrosoftTrustedRootProgramProvider _microsoftTrustedRootProgramProvider;
    private readonly IChromeRootStoreProvider _chromeRootStoreProvider;

    public IReadOnlyList<StoreCertificateRecord> Certificates { get; private set; } = Array.Empty<StoreCertificateRecord>();

    public DateTime RetrievedAtUtc { get; private set; }

    public int ChromeOverlapCount { get; private set; }

    public ProgramCertificatesModel(
        IMicrosoftTrustedRootProgramProvider microsoftTrustedRootProgramProvider,
        IChromeRootStoreProvider chromeRootStoreProvider)
    {
        _microsoftTrustedRootProgramProvider = microsoftTrustedRootProgramProvider;
        _chromeRootStoreProvider = chromeRootStoreProvider;
    }

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        var microsoftTask = _microsoftTrustedRootProgramProvider.GetCertificatesAsync(cancellationToken);
        var chromeTask = _chromeRootStoreProvider.GetCertificatesAsync(cancellationToken);

        var microsoftProgramRoots = await microsoftTask;
        var chromeRoots = await chromeTask;

        var chromeThumbprints = new HashSet<string>(chromeRoots.Select(cert => cert.Thumbprint), StringComparer.OrdinalIgnoreCase);

        var records = new List<StoreCertificateRecord>(microsoftProgramRoots.Count);

        foreach (var certificate in microsoftProgramRoots)
        {
            var record = CertificateRecordMapper.FromMicrosoftTrustedRootProgram(certificate);
            var presentInChrome = chromeThumbprints.Contains(certificate.Thumbprint);

            if (presentInChrome)
            {
                ChromeOverlapCount++;
            }

            records.Add(new StoreCertificateRecord(record, presentInChrome));
        }

        Certificates = records
            .OrderBy(r => r.Certificate.Subject, StringComparer.OrdinalIgnoreCase)
            .ThenBy(r => r.Certificate.Thumbprint, StringComparer.OrdinalIgnoreCase)
            .ToList();

        RetrievedAtUtc = DateTime.UtcNow;
    }
}
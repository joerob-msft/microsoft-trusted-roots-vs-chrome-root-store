using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace TrustedRootsVsChrome.Web.Services;

public sealed class CertificateSynchronizationBackgroundService : BackgroundService
{
    private static readonly TimeSpan RefreshInterval = TimeSpan.FromHours(12);

    private readonly IMicrosoftTrustedRootProgramRefreshService _refreshService;
    private readonly ILogger<CertificateSynchronizationBackgroundService> _logger;

    public CertificateSynchronizationBackgroundService(
        IMicrosoftTrustedRootProgramRefreshService refreshService,
        ILogger<CertificateSynchronizationBackgroundService> logger)
    {
        _refreshService = refreshService;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Starting certificate synchronization background service");

        await RunRefreshLoopAsync(stoppingToken).ConfigureAwait(false);

        _logger.LogInformation("Stopping certificate synchronization background service");
    }

    private async Task RunRefreshLoopAsync(CancellationToken stoppingToken)
    {
        var timer = new PeriodicTimer(RefreshInterval);

        // Perform an initial refresh on startup.
        await RefreshOnceAsync(stoppingToken).ConfigureAwait(false);

        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                await RefreshOnceAsync(stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Graceful shutdown.
        }
        finally
        {
            timer.Dispose();
        }
    }

    private async Task RefreshOnceAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _refreshService.RefreshAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Background refresh of Microsoft Trusted Root Program certificates failed");
        }
    }
}
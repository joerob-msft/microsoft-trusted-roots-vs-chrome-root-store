using TrustedRootsVsChrome.Web.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages();
builder.Services.AddMemoryCache();
builder.Services.AddSingleton<ICertificateCacheStore, FileCertificateCacheStore>();
builder.Services.AddSingleton<CertificateRefreshStatusTracker>();
builder.Services.AddSingleton<ICertificateRefreshStatusProvider>(sp => sp.GetRequiredService<CertificateRefreshStatusTracker>());
builder.Services.AddSingleton<ICertificateRefreshStatusUpdater>(sp => sp.GetRequiredService<CertificateRefreshStatusTracker>());

builder.Services.AddHttpClient<IChromeRootStoreProvider, ChromeRootStoreProvider>(client =>
{
    client.Timeout = TimeSpan.FromSeconds(30);
    client.DefaultRequestHeaders.UserAgent.ParseAdd("TrustedRootsVsChrome/1.0");
});
builder.Services.AddHttpClient<MicrosoftTrustedRootProgramProvider>(client =>
{
    client.Timeout = TimeSpan.FromMinutes(5);
    client.DefaultRequestHeaders.UserAgent.ParseAdd("TrustedRootsVsChrome/1.0");
});
builder.Services.AddSingleton<IMicrosoftTrustedRootProgramProvider>(sp => sp.GetRequiredService<MicrosoftTrustedRootProgramProvider>());
builder.Services.AddSingleton<IMicrosoftTrustedRootProgramRefreshService>(sp => sp.GetRequiredService<MicrosoftTrustedRootProgramProvider>());
builder.Services.AddSingleton<CertificateComparisonService>();
builder.Services.AddHostedService<CertificateSynchronizationBackgroundService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapRazorPages();

app.Run();

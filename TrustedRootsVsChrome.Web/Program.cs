using TrustedRootsVsChrome.Web.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages();
builder.Services.AddMemoryCache();

builder.Services.AddHttpClient<IChromeRootStoreProvider, ChromeRootStoreProvider>(client =>
{
    client.Timeout = TimeSpan.FromSeconds(30);
    client.DefaultRequestHeaders.UserAgent.ParseAdd("TrustedRootsVsChrome/1.0");
});
builder.Services.AddHttpClient<IMicrosoftTrustedRootProgramProvider, MicrosoftTrustedRootProgramProvider>(client =>
{
    client.Timeout = TimeSpan.FromSeconds(30);
    client.DefaultRequestHeaders.UserAgent.ParseAdd("TrustedRootsVsChrome/1.0");
});
builder.Services.AddSingleton<IWindowsTrustedRootProvider, WindowsTrustedRootProvider>();
builder.Services.AddSingleton<CertificateComparisonService>();

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

# Copilot Instructions

## Project Snapshot
- **Solution**: `TrustedRootsVsChrome.sln` with two projects
  - `TrustedRootsVsChrome.Web` (Razor Pages, .NET 8) renders the dashboard and houses certificate services
  - `TrustedRootsVsChrome.Tests` (xUnit) covers comparison edge cases
- Target environment is **Azure App Service on Windows**; local development should mimic this to match certificate stores.

- `Services/ChromeRootStoreProvider` downloads the Chrome root bundle from `https://chromium.googlesource.com/.../root_store.certs?format=TEXT`, decodes the base64 payload, parses PEM blocks via `Regex`, and caches results for 12 hours with `IMemoryCache`.
- `Services/MicrosoftTrustedRootProgramProvider` retrieves the official `authroots.sst` feed from `http://ctldl.windowsupdate.com/...`, imports the serialized certificate store, and caches the result for 12 hours.
- `Services/WindowsTrustedRootProvider` enumerates both `CurrentUser` and `LocalMachine` root stores, deduplicating by thumbprint. Errors per store are logged and ignored so a single failure doesn't abort the load.
- `Services/CertificateComparisonService` orchestrates the comparison:
  - Fetches Chrome and Microsoft program feeds, joins in any Windows store metadata by thumbprint, and defaults each record's `Sources` to include "Microsoft Trusted Root Program".
  - Excludes certificates when their subject/issuer/friendly name contains "Microsoft" (toggle controlled in `Index`), then returns the sorted difference set.
  - Wraps errors in `CertificateComparisonResult.ErrorMessage` so the UI can show a friendly alert instead of crashing.
- Razor Page `Pages/Index` consumes the service on `OnGetAsync` and displays the difference table. The view expects `MissingInChrome` and respects the success/error states called out above.

## UI & Styling
- Layout is defined in `Pages/Shared/_Layout.cshtml`; navigation classes (`.app-header`, `.app-nav`, `.hero-panel`, `.status-card`, `.table-wrapper`) are implemented in `wwwroot/css/site.css`. Keep Bootstrap references intact; add new styles alongside the custom section at the top of `site.css`.
- The table expects `CertificateRecord` fields (Subject, Issuer, Thumbprint, NotBeforeUtc/NotAfterUtc, Version, FriendlyName). Preserve these when extending the model/UI.

## Workflows
- Restore/build/test with:
  - `dotnet restore`
  - `dotnet build`
  - `dotnet test`
- Run locally via `dotnet run --project TrustedRootsVsChrome.Web`. HTTPS redirection is enabled by default; trust the development cert if prompted.
- The app requires outbound HTTPS access to both `chromium.googlesource.com` (Chrome bundle) and `ctldl.windowsupdate.com` (Microsoft Trusted Root Program).

## Patterns & Conventions
- Prefer dependency injection with interface abstractions (`IChromeRootStoreProvider`, `IMicrosoftTrustedRootProgramProvider`, `IWindowsTrustedRootProvider`) to keep services testable.
- Cache remote certificate payloads using `IMemoryCache`; adjust the 12-hour window only if you understand the traffic trade-offs.
- Treat certificate comparison results as immutable responses (`CertificateComparisonResult` + `CertificateRecord`). Add fields by extending these models rather than leaking raw `X509Certificate2` instances into the UI.
- Tests create in-memory self-signed certificates using `CertificateRequest`. When writing new tests, dispose of any certificates you generate to avoid handle leaks.

## Deployment Considerations
- Azure App Service (Windows) already exposes the LocalMachine and CurrentUser root stores; no elevated permissions are required.
- Avoid storing secrets in config files. If new external services are added, prefer Managed Identity or Key Vault integration per Azure guidance.
- Log comparison failures via `ILogger` so they surface in App Service diagnostics.

## When Extending
- If pulling alternative trust stores, follow the provider pattern: fetch via `HttpClient`, cache with `IMemoryCache`, parse into `X509Certificate2` instances, and expose them behind a dedicated interface.
- For richer analytics, extend the Index page but keep loading logic in `IndexModel` to maintain separation of concerns.
- Update this document whenever you introduce new services, data flows, or developer workflows (e.g., background sync, storage, CI/CD scripts).

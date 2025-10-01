# Trusted Roots vs Chrome Root Store

A .NET 8 Razor Pages web application that highlights differences between the trusted root certificates installed on an Azure App Service (Windows) worker and the certificates included in Chrome's Root Store.

## Features

- Downloads the latest Chrome Root Store certificate bundle directly from the Chromium source repository.
- Reads the current worker's Windows trusted root store (both `CurrentUser` and `LocalMachine`).
- Excludes Microsoft-issued root certificates from the comparison.
- Presents missing certificates in a responsive, data-rich dashboard styled for modern browsers.

## Getting Started

### Prerequisites

- .NET SDK 8.0 (or later)
- Windows (for local store parity) or any OS for development

### Restore, Build, and Run

```powershell
# Restore packages
 dotnet restore

# Run tests
 dotnet test

# Launch the web application
 dotnet run --project TrustedRootsVsChrome.Web
```

Navigate to `https://localhost:5001` (or the HTTPS URL shown in the console). The homepage automatically runs the comparison and renders the results.

### Deployment Notes

- Target Azure App Service on Windows for parity with the certificate store logic.
- Managed identity is not required for certificate access; the app relies on the worker's local stores.
- Ensure outbound internet access is allowed so the app can download the Chrome Root Store file from `chromium.googlesource.com`.

## Project Structure

- `TrustedRootsVsChrome.Web/` — Razor Pages application with services and models
  - `Services/ChromeRootStoreProvider` — downloads and parses the Chrome root store bundle
  - `Services/WindowsTrustedRootProvider` — loads certificates from Windows trusted stores
  - `Services/CertificateComparisonService` — orchestrates the comparison and filtering logic
  - `Pages/Index` — dashboard UI for the comparison results
- `TrustedRootsVsChrome.Tests/` — xUnit tests covering comparison edge cases

## Known Limitations

- The Chrome root store is cached in-memory for 12 hours to limit network usage; restart the app to force an immediate refresh.
- Microsoft-issued certificates are excluded via a simple subject/issuer string match (`"Microsoft"`). Update the logic if more granular filtering is required.

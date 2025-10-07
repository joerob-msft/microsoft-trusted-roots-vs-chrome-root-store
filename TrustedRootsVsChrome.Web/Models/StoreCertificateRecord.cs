namespace TrustedRootsVsChrome.Web.Models;

public sealed record StoreCertificateRecord(
    CertificateRecord Certificate,
    bool PresentInOtherStore);
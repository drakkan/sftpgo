# Security Policy

## Supported Versions

We actively maintain the latest stable release of SFTPGo. While we strive to keep the Open Source version secure and up-to-date, maintenance is performed on a best-effort basis by the community and contributors.

## Scope and Dependency Policy

Our security advisories focus on vulnerabilities found within the **SFTPGo codebase itself**.

To ensure the long-term sustainability of the project, we handle upstream dependencies (like the Go standard library, external packages, or Docker base images) as follows:

- Community Updates: For the Open Source version, vulnerabilities in upstream components (such as the Go standard library or third-party packages) are addressed during our **regular release cycles**. We generally do not provide immediate, out-of-band or ad-hoc releases to address dependency-only CVEs.
- Empowering Users: One of the strengths of SFTPGo being open-source is that you have full control. If your security scanners require an immediate fix, you can always rebuild the project using the latest patched Go toolchain or updated dependencies.
- Compatibility: We are committed to keeping SFTPGo compatible with the latest stable Go compiler. If an upstream fix breaks SFTPGo, fixing that becomes a priority for us.
- Professional Needs: We understand that some organizations have strict compliance requirements or internal SLAs that require guaranteed, immediate response times and out-of-band patches. For these cases, we offer [SFTPGo Enterprise](https://sftpgo.com/on-premises) to cover the additional maintenance and support overhead.

## Reporting a Vulnerability

To report (possible) security issues in SFTPGo, please either send a mail to the [SFTPGo Team](mailto:support@sftpgo.com) or use Github's [private reporting feature](https://github.com/drakkan/sftpgo/security/advisories/new).

# Security Policy

We take genuine security issues in SFTPGo seriously, and we appreciate the time
researchers spend to responsibly report them. Real vulnerabilities are very
welcome and are fixed quickly. We focus our detailed analysis on findings that
have been verified and reproduced; unverified or automated checklist output
receives a correspondingly brief response. This document makes that line
explicit, so good-faith researchers know exactly what is actionable before they
invest their time.

## Supported Versions

Security fixes are applied to the latest stable release of SFTPGo. The Open
Source edition is actively maintained by the maintainers and contributors:
valid issues are prioritized and shipped as part of regular development,
without the formal response-time guarantees of a commercial support contract.
Organizations that need guaranteed response times, SLAs, or out-of-band patches
can use [SFTPGo Enterprise](https://sftpgo.com/on-premises).

## Reporting a Vulnerability

Please report suspected security issues **privately**, either by email to the
[SFTPGo Team](mailto:support@sftpgo.com) or through GitHub's
[private vulnerability reporting](https://github.com/drakkan/sftpgo/security/advisories/new).

Do not open public issues or pull requests for undisclosed security problems.

## What to Include

A report is actionable when it lets us understand and reproduce the issue
without guesswork. Please include:

- The SFTPGo version and edition, and the platform it runs on.
- The relevant configuration, with secrets redacted.
- Clear, step-by-step reproduction instructions.
- A concrete description of the impact: what an attacker can do, and which
  security boundary (authentication, authorization, account isolation,
  confidentiality, integrity) is crossed.
- A proof of concept where applicable.

Please report only behavior you have personally reproduced and understood on a
current, supported release in a reasonable default configuration.

## What We Consider a Vulnerability

The deciding question is simple: **does SFTPGo's own code let an attacker cross
a security boundary it is responsible for enforcing, in a reasonable default
configuration the operator did not deliberately weaken?**

If yes, it is a vulnerability and we want to know. Examples: authentication
bypass, privilege escalation, path traversal outside a user's home directory,
breaking isolation between accounts, or SFTPGo emitting attacker-controlled
content in a way that crosses a trust boundary. These are fixed in code and
receive a security advisory. Please bring them to us.

If the answer depends on an optional, operator-owned protection not being
enabled, it is not a vulnerability. SFTPGo deliberately ships usable defaults
and exposes hardening controls so each operator can choose a posture for their
own threat model; a default that is not the most restrictive possible is an
intentional trade-off. The following are **out of scope** as security
advisories — **regardless of whether the specific control is individually named
in the documentation**, and **regardless of an attached generic proof of
concept**:

- The absence, permissiveness, or non-default state of an optional
  defense-in-depth control: the defender, rate limiting, IP allow/deny lists,
  multi-factor authentication, and HTTP security response headers such as
  Content-Security-Policy, Strict-Transport-Security, X-Frame-Options,
  Referrer-Policy, Permissions-Policy and similar. Clickjacking, framing, or
  "missing header X" findings whose only remediation is enabling one of these
  controls fall here.
- Behavior that requires an administrator to deliberately weaken or disable a
  security control, or to choose an insecure configuration (for example a weak
  operator-chosen secret).
- Generic best-practice or compliance-scanner checklist items (TLS version,
  cookie flags, version disclosure, directory listing) with no demonstrated
  code-level security impact.
- Theoretical findings with no demonstrated, realistic impact.
- Issues that depend only on access the reporter already legitimately has,
  without additional impact.

The distinction is the nature of the issue, not the volume of documentation or
the presence of a screenshot: a flaw in SFTPGo's code is in scope even if a
hardening control could also have mitigated it; the mere absence of that
hardening control is not in scope, even with a generic demonstration.

Out-of-scope reports are still welcome as ordinary improvement suggestions —
they are triaged as normal hardening work rather than security advisories. The
available hardening controls, and how to configure them, are described in the
documentation.

## AI-Assisted and Automated Reports

Automated tools, including scanners and AI assistants, are a legitimate aid and
we have no objection to their use. We do ask that you submit only findings
**you have verified yourself**: reproduced on a current, supported release,
understood, and able to explain and discuss in your own words.

We focus our detailed analysis on reports that meet this bar. Unverified,
machine-generated submissions — batches of generic findings, results that do
not actually apply to SFTPGo, or claims the reporter cannot substantiate or
reproduce — receive a brief response rather than a full investigation, so that
we can give genuine issues the attention they deserve.

This is not aimed at good-faith researchers. One carefully verified report is
far more valuable to us, and to you, than a large volume of unconfirmed ones,
and we would much rather spend that time working with you on a real issue.

## Recognition and Rewards

SFTPGo does **not** operate a paid bug bounty program and does not offer
monetary rewards for security reports. We credit the reporter of a valid,
original issue in the commit and/or in the published security advisory, unless
you ask to remain anonymous.

A report is triaged and acted on purely on its technical merits. Requests for
payment, bug-bounty-platform invoicing, or sponsorship do not change that in
either direction: a genuine vulnerability is still fixed and credited
regardless of any such request, and we will not pay for it. Please do not make
a report contingent on payment — the condition is disregarded, not the finding.

## Dependency Policy

Our security advisories focus on vulnerabilities in the **SFTPGo codebase
itself**. Upstream dependencies (the Go standard library, third-party packages,
Docker base images) are handled as follows:

- For the Open Source edition, dependency vulnerabilities are addressed during
  our **regular release cycles**. We generally do not issue out-of-band or
  ad-hoc releases for dependency-only CVEs.
- Because SFTPGo is open source, you can rebuild it at any time with a patched
  Go toolchain or updated dependencies if your scanners require an immediate
  fix.
- We keep SFTPGo compatible with the latest stable Go compiler. If an upstream
  fix breaks SFTPGo, addressing that is a priority for us.
- Organizations with strict compliance requirements or internal SLAs that need
  guaranteed, immediate, out-of-band patches can use
  [SFTPGo Enterprise](https://sftpgo.com/on-premises).

# SFTPGo

[![CI Status](https://github.com/drakkan/sftpgo/workflows/CI/badge.svg)](https://github.com/drakkan/sftpgo/workflows/CI/badge.svg)
[![License: AGPL-3.0-only](https://img.shields.io/badge/License-AGPLv3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Mentioned in Awesome Go](https://awesome.re/mentioned-badge.svg)](https://github.com/avelino/awesome-go)

Full-featured and highly configurable event-driven file transfer solution. Server protocols: SFTP, HTTP/S, FTP/S, WebDAV. Storage backends: local filesystem, encrypted local filesystem, S3 (compatible) Object Storage, Google Cloud Storage, Azure Blob Storage, other SFTP servers.

With SFTPGo you can leverage local and cloud storage backends for exchanging and storing files internally or with business partners using the same tools and processes you are already familiar with.

## Project Status & Editions

SFTPGo is an open-source project with a sustainable business model. We offer two editions to suit different requirements, ensuring the project remains healthy and maintained for everyone.

### Open Source (Community)

Free, Copyleft (AGPLv3), Community Supported. The Community edition is a fully functional, production-ready solution widely adopted worldwide. It includes all the core protocols, storage backends, and the WebAdmin/WebClient UIs. It is ideal for:

- Standard file transfer needs.
- Integrating storage backends (S3, GCS, Azure Blob) with legacy protocols.
- Projects that are comfortable with AGPLv3 licensing.

### SFTPGo Enterprise

Commercial License, Professional Support, ISO 27001 Vendor. The Enterprise edition is built on the same core but extends it for mission-critical environments, compliance-heavy industries, and advanced workflows. It is a drop-in replacement (seamless upgrade).

| Feature | Open Source (Community) | Enterprise Edition |
| :--- | :--- | :--- |
| **License Type** | AGPLv3 (Copyleft) | **Commercial License**<br/>Proprietary/No Copyleft |
| **Vendor Compliance** | Not Applicable<br/>Community Project | **Certified Vendor**<br/>ISO 27001 & Supply Chain Validation |
| **Support** | Community (GitHub) | **Direct from Authors** |
| **Cloud Storage Engine** | Standard | **High Performance & Scalable**<br/>In-memory streaming (no local temp files) and up to 70% faster |
| **High Availability (HA)** | Standard<br/>Shared DB & Storage | **Advanced**<br/>Enhanced event handling and optimized instance coordination |
| **Automation Logic** | Simple Placeholders | **Dynamic Logic & Virtual Folders**<br/>Conditions, loops, route data across storage backends |
| **Data Lifecycle** | Delete / Retain | **Smart Archiving**<br/>Move data to external Cloud/SFTP storage via Virtual Folders |
| **Email Data Ingestion** | - | **Native IMAP Integration**<br/>Auto-extract attachments from email to storage |
| **Public Sharing** | Standard Links | **Advanced & Collaborative**<br/>Email Authentication & Group Delegation |
| **Data Protection** | - | **Encryption & Scanning**<br/>Automated PGP, Antivirus & DLP via ICAP |
| **Advanced Identity (SSO)** | Standard | **Extended Controls**<br/>Advanced Single Sign-On parameters |
| **Document Editing** | - | **Included**<br/>View, edit, and co-author in browser |

**Note**: We are committed to keeping the Open Source edition powerful and maintained. The Enterprise edition helps fund the development of the entire SFTPGo ecosystem.

## Sponsors

If you rely on SFTPGo in your projects, consider becoming a [sponsor](https://github.com/sponsors/drakkan).

Your sponsorship helps cover maintenance, security updates and ongoing development of the open-source edition.

### Thank you to our sponsors

#### Platinum sponsors

[<img src="./img/Aledade_logo.png" alt="Aledade logo" width="202" height="70">](https://www.aledade.com/)
</br></br>
[<img src="./img/jumptrading.png" alt="Jump Trading logo" width="362" height="63">](https://www.jumptrading.com/)
</br></br>
[<img src="./img/wpengine.png" alt="WP Engine logo" width="331" height="63">](https://wpengine.com/)

#### Silver sponsors

[<img src="./img/IDCS.png" alt="IDCS logo" width="212" height="51">](https://idcs.ip-paris.fr/)

#### Bronze sponsors

[<img src="./img/7digital.png" alt="7digital logo" width="178" height="56">](https://www.7digital.com/)
</br></br>
[<img src="./img/servinga.png" alt="servinga logo" width="258" height="56">](https://servinga.com/)
</br></br>
[<img src="./img/reui.png" alt="ReUI logo" width="151" height="56">](https://www.reui.io/)

## Documentation

You can explore all supported features and configuration options at [docs.sftpgo.com](https://docs.sftpgo.com/latest/).

**Note:** The link above refers to the **Community Edition**.
For details on **Enterprise Edition**, please refer to the [Enterprise Documentation](https://docs.sftpgo.com/enterprise/).

## Support

- **Community Support**: use [GitHub Discussions](https://github.com/drakkan/sftpgo/discussions) to ask questions, share feedback, and engage with other users.
- **Commercial Support**: If you require guaranteed SLAs, expert guidance, or the advanced features listed above, check out [SFTPGo Enterprise](https://sftpgo.com).

SFTPGo Enterprise is available as:

- On-premises: Full control on your infrastructure. More details: [sftpgo.com/on-premises](https://sftpgo.com/on-premises)
- Fully managed SaaS: We handle the infrastructure. More details: [sftpgo.com/saas](https://sftpgo.com/saas)

## Internationalization

The translations are available via [Crowdin](https://crowdin.com/project/sftpgo), who have granted us an open source license.

Before translating please take a look at our contribution [guidelines](https://docs.sftpgo.com/latest/web-interfaces/#internationalization).

## Release Cadence

SFTPGo follows a feature-driven release cycle.

- Enterprise Edition: Receives major new features first and follows a faster [release cadence](https://docs.sftpgo.com/enterprise/changelog/).
- Community Edition: Remains maintained, receiving bug fixes, security updates, and updates to core features.

## Acknowledgements

SFTPGo makes use of the third party libraries listed inside [go.mod](./go.mod).

We are very grateful to all the people who contributed with ideas and/or pull requests.

Thank you to [ysura](https://www.ysura.com/) for granting us stable access to a test AWS S3 account.

Thank you to [KeenThemes](https://keenthemes.com/) for granting us a custom license to use their amazing [themes](https://keenthemes.com/bootstrap-templates) for the SFTPGo WebAdmin and WebClient user interfaces, across both the Open Source and Open Core versions.

Thank you to [Crowdin](https://crowdin.com/) for granting us an Open Source License.

Thank you to [Incode](https://www.incode.it/) for helping us to improve the UI/UX.

## License

SFTPGo source code is licensed under the GNU AGPL-3.0-only with [additional terms](./NOTICE).

The [theme](https://keenthemes.com/bootstrap-templates) used in WebAdmin and WebClient user interfaces is proprietary, this means:

- KeenThemes HTML/CSS/JS components are allowed for use only within the SFTPGo product and restricted to be used in a resealable HTML template that can compete with KeenThemes products anyhow.
- The SFTPGo WebAdmin and WebClient user interfaces (HTML, CSS and JS components) based on this theme are allowed for use only within the SFTPGo product and therefore cannot be used in derivative works/products without an explicit grant from the [SFTPGo Team](mailto:support@sftpgo.com).

More information about [compliance](https://sftpgo.com/compliance.html).

**Note:** We do not provide legal advice. If you have questions about license compliance or whether your use case is permitted under the license terms, please consult your legal team.

## Copyright

Copyright (C) 2019 - 2026 Nicola Murino

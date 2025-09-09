# SFTPGo

[![CI Status](https://github.com/drakkan/sftpgo/workflows/CI/badge.svg)](https://github.com/drakkan/sftpgo/workflows/CI/badge.svg)
[![License: AGPL-3.0-only](https://img.shields.io/badge/License-AGPLv3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Mentioned in Awesome Go](https://awesome.re/mentioned-badge.svg)](https://github.com/avelino/awesome-go)

Full-featured and highly configurable event-driven file transfer solution.
Server protocols: SFTP, HTTP/S, FTP/S, WebDAV.
Storage backends: local filesystem, encrypted local filesystem, S3 (compatible) Object Storage, Google Cloud Storage, Azure Blob Storage, other SFTP servers.

With SFTPGo you can leverage local and cloud storage backends for exchanging and storing files internally or with business partners using the same tools and processes you are already familiar with.

The WebAdmin UI allows to easily create and manage your users, folders, groups and other resources.

The WebClient UI allows end users to change their credentials, browse and manage their files in the browser and setup two-factor authentication which works with Microsoft Authenticator, Google Authenticator, Authy and other compatible apps.

## Sponsors

SFTPGo remains committed to open source. The core features are freely available and maintained.
If you rely on SFTPGo in your projects, consider becoming a [sponsor](https://github.com/sponsors/drakkan) to help ensure its long-term sustainability.

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

## Support

SFTPGo is free to use under the terms of its Open Source [license](#license). We are proud to offer a powerful and fully functional open source edition that is suitable for many production use cases.

While we do not offer direct free support, community support is available. You can use [GitHub Discussions](https://github.com/drakkan/sftpgo/discussions) to ask questions, share feedback and engage with other users of the project.

If you require guaranteed support, expert guidance, or advanced features, consider using SFTPGo Enterprise: a commercially licensed edition of SFTPGo that extends the open source version with enterprise-only features and full support.

SFTPGo Enterprise is available in two deployment options:

- On-premises: Deploy on your own infrastructure with full control and commercial-grade support. More details: [sftpgo.com/on-premises](https://sftpgo.com/on-premises)
- Fully managed SaaS: Let us handle the infrastructure. Ideal for teams that want a secure, scalable, and maintenance-free setup with full support included. More details: [sftpgo.com/saas](https://sftpgo.com/saas)

## Documentation

You can explore all supported features and configuration options at [docs.sftpgo.com](https://docs.sftpgo.com/).

In the top-left corner of the documentation site, you can select the version you're using.
If you're using the open-source edition, do not select the "Enterprise" docs, as they describe features only available in the licensed version or our SaaS offerings.

## Internationalization

The translations are available via [Crowdin](https://crowdin.com/project/sftpgo), who have granted us an open source license.

Before start translating please take a look at our contribution [guidelines](https://sftpgo.github.io/latest/web-interfaces/#internationalization).

## Release Cadence

SFTPGo follows a feature-driven release cycle rather than a fixed, time-based schedule. Currently, our primary development efforts are focused on the [Enterprise edition](https://docs.sftpgo.com/enterprise/#enterprise-edition), which benefits from a faster release cadence and receives major new features (see [changelog](https://docs.sftpgo.com/enterprise/changelog/)).

This open-source version of SFTPGo remains maintained and will continue to receive bug fixes and essential updates. However, not all enhancements introduced in the Enterprise edition will be available.

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

Copyright (C) 2019 - 2025 Nicola Murino

# Linux cryptocurrency artifacts

Research and implementation: 2026-10-10. Findings appear in the **Cryptocurrency**
category during live triage, collapsed until expanded like other categories.
The data-only [support index](../artifacts/cryptocurrency/index.json) records paths,
parsers, references and limits. Only selected targets are read. Existing all-artifacts
and matches-only modes are preserved; wallet identification does not override match
requirements. Raw evidence and source SHA256 continue into ZIP/PDF/JSONL/CSV exports.

| Application | Collected/recognized | Interpretation |
| --- | --- | --- |
| Bitcoin/Litecoin Core | Known wallet.dat/backup paths, wallet database companions, configuration, debug/db logs, settings and peer files | SQLite/BDB container recognition; selected non-secret configuration settings. Wallet keys/transaction bodies remain raw. Peer/node data does not prove wallet ownership. |
| Electrum / Electron Cash | Wallet directories, network subdirectories; Electrum configuration/logs/certificates | Bounded JSON wallet type/version, stored address strings and transaction IDs. ECIES prefixes on known wallet paths stay locked. Network, address ownership and chain confirmation are not inferred. |
| Ethereum/Geth | Known keystore directories, renamed recognized V3 JSON keyfiles | Public address, file ID, cipher and KDF parameters. Cipher/IV/MAC structure checked; MAC is not verified and private keys are not decrypted. |
| Monero | Known Monero/wallets and .bitmonero wallet/log candidates | Raw collection. CLI wallets may be stored anywhere; arbitrary .keys files are not automatically declared Monero wallets. |
| Exodus | Known Linux wallet, backup and configuration/log paths | Raw collection; proprietary/encrypted content remains opaque. |
| Wasabi | Wallets, WalletBackups and known configuration/log files | Path/container metadata; encrypted proprietary values remain raw. |
| Sparrow | Legacy home, network wallet subdirectories and default XDG wallet/config/log paths | Raw collection. Custom -d/XDG paths require the examiner to select them. |
| MetaMask | Official Chrome extension ID's Local Extension Settings and installation manifest | CRC-checked physical LevelDB observations; CURRENT/MANIFEST preserved raw. Vaults stay encrypted. Extension installation is not proof of use or authenticity. |

Renamed Electrum-compatible and Ethereum V3 JSON wallets can be recognized from
complete acquired JSON outside default directories. JSON interpretation is bounded
to 4 MiB and record summaries to 10000 entries. Unsupported/encrypted/oversized
formats remain raw or partial. Generic filename extensions and isolated address-like
strings are not treated as proof of a wallet. No wallet client, transaction signing,
network balance check, RPC, automatic target expansion or evidence upload occurs.

## Research trail

Application source/documentation supplied the implemented Linux paths and schemas:

- [Bitcoin Core files](https://github.com/bitcoin/bitcoin/blob/master/doc/files.md),
  [Litecoin Core files](https://github.com/litecoin-project/litecoin/blob/master/doc/files.md).
- [Electrum FAQ](https://electrum.readthedocs.io/en/latest/faq.html),
  [wallet schema](https://github.com/spesmilo/electrum/blob/master/electrum/wallet_db.py),
  [encrypted storage](https://github.com/spesmilo/electrum/blob/master/electrum/storage.py),
  [Electron Cash configuration](https://github.com/Electron-Cash/Electron-Cash/blob/master/electroncash/simple_config.py).
- [Geth backup/keystore directories](https://geth.ethereum.org/docs/fundamentals/backup-restore),
  [V3 schema](https://github.com/ethereum/go-ethereum/blob/master/accounts/keystore/key.go).
- [Monero wallet file options](https://docs.getmonero.org/interacting/monero-wallet-cli-reference/),
  [Exodus Linux backups](https://www.exodus.com/support/en/articles/8598708-how-do-i-rescue-an-overwritten-wallet),
  [Wasabi data folder](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html),
  [Sparrow and XDG locations](https://sparrowwallet.com/docs/faq.html),
  [official MetaMask extension](https://chromewebstore.google.com/detail/metamask/nkbihfbeogaeaoehlefnkodbefgpgknn).

Other triage/research references were reviewed without executing their tools:

- [KAPE wallet keyword modules](https://github.com/EricZimmerman/KapeFiles/blob/master/Modules/Compound/bstrings_CryptoWallets.mkape)
  use bstrings searches, rather than supplying a Linux wallet-path collector. TERRA
  does not invoke Windows binaries or copy broad regex hits into confirmed wallets.
- The current [UAC tree](https://github.com/tclahr/uac/tree/main/artifacts) and
  [Velociraptor tree](https://github.com/Velocidex/velociraptor/tree/master/artifacts/definitions)
  were inspected. No dedicated cryptocurrency-named Linux collector was identified
  in those trees; Generic.Utils.Crypto is cryptographic utility code, not wallet coverage.
- [SANS Litecoin research](https://www.sans.org/white-papers/34595) provided historical
  forensic context; current Linux definitions rely on Litecoin's source documentation.
- [Linux Exodus/Electrum thesis](https://hh.diva-portal.org/smash/get/diva2%3A1671204/FULLTEXT02.pdf)
  and [2024 desktop-wallet paper](https://www.scitepress.org/Papers/2024/123130/123130.pdf)
  were downloaded and read locally as PDFs. Their older/platform-specific observations
  were cross-checked against current application documentation; Windows paths were
  not transplanted into Linux rules.
- [Hexordia's wallet-forensics research](https://www.hexordia.com/blog/cryptocurrency)
  was reviewed as broader mobile context, without treating mobile paths as Linux paths.

## Validation and changed files

Synthetic tests verify path families, negative cases, renamed-wallet recognition,
public summaries, locked keystores, selected scope, matches-only behavior, collapsed
live categories, source hashes and portable structured export. The original files
remain unchanged. These tests do not establish every wallet version or corruption case.

Changes: `artifacts/cryptocurrency/{index.json,parser.py,__init__.py}`, catalog/parsing
dispatch, scan-controller content recognition, and `tests/test_cryptocurrency.py`.

The same update sets image similarity to a default **70%**, adjustable **1–100%**
under **Minimum image similarity score**; the actual selected threshold is recorded
in match findings. Changes are confined to the image matcher, worker, configuration
controller/UI, its tests and image-similarity documentation.

Welcome branding uses the original `assets/icons/TERRA Forensic Triage.png` without
altering it. `interface/widgets/branding.py` paints edges into the existing grey;
only the welcome page embeds the illustration. MainWindow/main.py set Qt window and
application icons and the `terra` desktop identity. XFCE/X11 can use the window icon;
Wayland desktops may resolve panel icons through an installed matching desktop entry,
which must be included when packaging the application. No desktop files or settings
are silently installed on the examined system. The welcome was rendered at 960×640
and the existing 620×460 minimum size.

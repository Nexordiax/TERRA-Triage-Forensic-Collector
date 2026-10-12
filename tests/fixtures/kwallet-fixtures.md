# Independent classic KWallet fixtures

Known password: `fixture-wallet-password`; one `Chromium Keys` folder containing
the `Chromium Safe Storage` password `fixture-safestorage`. No real credentials.

`make_kwallet_fixture.py` writes legacy SHA1/ECB, legacy SHA1/CBC and modern
PBKDF2-SHA512/CBC stores. Encryption uses KDE's unmodified native `BlowFish` class
from [KWallet v6.18.0](https://github.com/KDE/kwallet/tree/v6.18.0/src/runtime/kwalletbackend)
with a small development C wrapper that sets the key, XORs the previous ciphertext
block for CBC, and calls `BlowFish::encrypt` on each eight-byte block.
KDE source files and compiled libraries are not bundled in TERRA.
The Python generator independently builds the documented QDataStream payload
and password material; it does not import the application's decoder.

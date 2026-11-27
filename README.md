# Secure Password Vault (`ics0022_lab`)

A modular, offline C# + WPF (`.NET 10`, Windows) local password manager built for the ICS0022 Secure Programming workshop (`AI_Password_Manager_Workshop.pdf`), applying the defense-in-depth architecture from `report.pdf`.

## Project Structure

```text
PasswordVault.sln
├── Directory.Build.props
├── src/
│   ├── PasswordVault.Core/        # Domain models, cryptography, validation, ACL storage, session
│   │   ├── Models/                # VaultHeader, VaultEntry, VaultEntrySummary, typed VaultExceptions
│   │   ├── Security/              # Argon2id KDF, AES-256-GCM + AAD, binary VaultSerializer, SecretBuffer, InputValidator
│   │   ├── Storage/               # FileVaultStorage (atomic temp+move + ACL), FileAuditLog (pwm.log), WindowsAclHelper
│   │   └── Session/               # VaultSession, IdleTimer, IClock/SystemClock, WindowsUserIdentityProvider
│   └── PasswordVault.App/         # WPF XAML UI (MVVM, PasswordBox -> SecretBuffer, auto-clearing clipboard)
│       ├── Services/              # SecureStringHelper, SecureClipboardService
│       ├── ViewModels/            # MainViewModel, VaultEntryViewModel, ObservableObject, RelayCommand
│       └── Views/                 # MainWindow.xaml & MainWindow.xaml.cs
└── tests/
    └── PasswordVault.Tests/       # MSTest security, crypto, validation, ACL storage, and session tests
```

## Security Design

- **Key Derivation (Argon2id):** Derives 64 bytes from the UTF-8 master passphrase and a random 16-byte CSPRNG salt per vault using `BouncyCastle.Cryptography` (`m = 65536` KiB / 64 MiB, `t = 3`, `p = 1`, Argon2 v1.3). Bytes `[0..32]` become the AES-256 encryption key (`K_enc`); `SHA-256(D[32..64])` is stored in the header as the key verifier (`V`) and compared in constant time (`CryptographicOperations.FixedTimeEquals`) before decryption.
- **Authenticated Encryption (AES-256-GCM + AAD):** Encrypts the binary entry payload with `System.Security.Cryptography.AesGcm` (16-byte tag) and a fresh random 12-byte (96-bit) nonce on every save. Both the 80-byte `PWMV` header and the UTF-8 vault name are passed as Additional Authenticated Data (AAD).
- **Memory Hygiene:** Derived keys and entry passwords live in `SecretBuffer` instances zeroed via `CryptographicOperations.ZeroMemory` on lock, timeout, or disposal (`ToString()` returns `"[REDACTED]"`). WPF `PasswordBox` input is converted directly from `SecureString` unmanaged Unicode memory into `SecretBuffer` without allocating managed `string` passphrases.
- **Hardened Atomic Storage & Audit Log:** Vault files (`%LOCALAPPDATA%\SecurePasswordVault\default.vault`) are stored outside the repository under owner-only Windows ACLs with reparse-point (symlink/junction) rejection, directory locking (`.vault.lock`), write-through temp files, on-disk SHA-256 race detection, and secret-free structured audit logging (`pwm.log`).
- **Session & Clipboard Protection:** Sessions auto-lock after 5 minutes of inactivity or on Windows SID mismatch, and copied passwords are automatically cleared from the clipboard after 30 seconds (if unchanged) and on vault lock/exit.

## Prerequisites, Build, Run, and Test

- **Prerequisites:** Windows + [.NET 10 SDK](https://dotnet.microsoft.com/) (verified with SDK `10.0.402`).

```powershell
# Build solution in Release mode
dotnet build PasswordVault.sln -c Release

# Run the WPF application
dotnet run --project src/PasswordVault.App -c Release

# Run the security & unit test suite
dotnet test PasswordVault.sln -c Release --verbosity normal
```

## Workshop Verification Checklist

1. Launch the app (`dotnet run --project src/PasswordVault.App`), create a vault with a 16+ character master passphrase, and add a fictional website, username, and password.
2. Lock or close and reopen the app; confirm an incorrect passphrase is rejected and the `.vault` file under `%LOCALAPPDATA%\SecurePasswordVault` remains unchanged.
3. Inspect the `.vault` file and confirm neither your master passphrase nor saved entry passwords appear as plaintext.
4. Keep `.vault`, `.log`, `.tmp`, and SonarQube scan tokens out of Git (`.gitignore` excludes `*.vault`, `*.log`, `*.tmp`, `.vault.lock`, `bin/`, `obj/`, `.sonarqube/`).
5. Scan the repository once with SonarQube Cloud Free or SonarQube Community Build (`dotnet-sonarscanner` for `.sln` projects).


## AI Disclaimer

This repository contains a password manager application generated with the help of AI. It was created for coursework practice to explore how AI can generate an application and to assess the security of the resulting code.

This application is intended for educational and testing purposes only. Its security has not been verified, so do not use it to store real passwords or other sensitive information.

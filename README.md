# wings-borg (Pterodactyl Wings + Borg backups)

> ⚠️ **Status: Experimental / In Development**  
> This fork ships a custom Wings binary that adds **BorgBackup** support. It may contain bugs or breaking changes.  
> If you hit an issue or want to contribute, please **open an issue** or submit a **Pull Request**.

This project integrates **[BorgBackup](https://www.borgbackup.org/)** into **Wings** (the Pterodactyl node daemon).  
It enables **creating, restoring, and deleting** backups with Borg, using a **per-server repository**, **no automatic pruning**, streaming restores (low RAM usage), and normalized metadata (correct file times).

---

## ✨ Features

- **New backup adapter: `borg`** for Wings.
- **Per-server Borg repositories**: `/var/lib/pterodactyl/backups/borg/<SERVER_UUID>`.
- **Create** with `zstd` compression (fallback to `lz4` when `zstd` isn’t available).
- **Restore in streaming** via `borg extract --stdout` (no large memory spikes).
- **No prune**: backups are **permanent** until a user deletes them (or the server is removed).
- Panel shows checksum as `borg:<uuid>` for easy identification.

---

## 📦 Requirements

- Linux node (Debian/Ubuntu recommended).
- **BorgBackup 1.2.x** installed:
  ```bash
  sudo apt-get update && sudo apt-get install -y borgbackup
  borg --version
  ```
- Go toolchain (to build the Wings binary).

---

## 🔧 Installation (Wings / Node)

1) **Clone and build**:
   ```bash
   git clone https://github.com/lilymelodev/wings-borg.git
   cd wings-borg
   go build
   ```

2) **Install the binary**:
   ```bash
   sudo systemctl stop wings
   sudo install -m 755 -o root -g root ./wings /usr/local/bin/wings
   sudo systemctl start wings
   ```

> The adapter generates **one passphrase per server** at `/etc/pterodactyl/borg/<SERVER_UUID>.pass` (mode `600`) and initializes each server repository automatically on first use.

---

## 🖥️ Panel Integration

> The Panel does not store Borg data; it **orchestrates** backups. We map `borg` to the existing Wings adapter on the Panel side.

1) `config/backups.php` — add the `borg` disk (and optionally make it the default):
```php
<?php

use Pterodactyl\Models\Backup;

return [
    'default' => env('APP_BACKUP_DRIVER', Backup::ADAPTER_BORG),

    'presigned_url_lifespan' => env('BACKUP_PRESIGNED_URL_LIFESPAN', 60),
    'max_part_size' => env('BACKUP_MAX_PART_SIZE', 5 * 1024 * 1024 * 1024),
    'prune_age' => env('BACKUP_PRUNE_AGE', 360),

    'throttles' => [
        'limit' => env('BACKUP_THROTTLE_LIMIT', 2),
        'period' => env('BACKUP_THROTTLE_PERIOD', 600),
    ],

    'disks' => [
        'wings' => ['adapter' => Backup::ADAPTER_WINGS],
        's3'    => [/* ... S3 config ... */],

        // New: treat 'borg' as a disk the Panel can orchestrate
        'borg'  => ['adapter' => Backup::ADAPTER_BORG],
    ],
];
```

2) `/app/Models/backups.php` — Add the new adapter:
```php
class Backup extends Model
{
    use SoftDeletes;

    public const RESOURCE_NAME = 'backup';

    public const ADAPTER_WINGS = 'wings';
    public const ADAPTER_AWS_S3 = 's3';
    public const ADAPTER_BORG  = 'borg'; // Add the new adapter
```

3) `app/Extensions/Backups/BackupManager.php` — support the `borg` adapter by mapping it to `wings`:
```php
protected function createBorgAdapter(array $config): FilesystemAdapter
{
    // Treat 'borg' just like 'wings'; the node does the real work.
    return $this->createWingsAdapter($config);
}
```

3) Clear Panel caches:
```bash
php artisan config:clear
php artisan optimize:clear
php artisan queue:restart
php artisan optimize
```

---

## ▶️ Usage

- **Create backup**: from the Panel (use disk `borg` or set it as default). The node initializes the repo (if needed) and creates an archive named after the **backup UUID**.
- **Restore backup**: from the Panel, the node streams files back to the server directory (paths are normalized to the server root; mtimes are parsed correctly).
- **Delete backup**: from the Panel or API — the node runs `borg delete repo::uuid`.

**Quick verification on the node:**
```bash
S=<SERVER_UUID>
B=<BACKUP_UUID>
borg list /var/lib/pterodactyl/backups/borg/$S
borg list --json-lines /var/lib/pterodactyl/backups/borg/$S::$B | head
```

---

## 🧰 Troubleshooting

- **Panel: “Adapter [borg] is not supported”**  
  Add `createBorgAdapter()` (see above) and clear config cache.

- **Wings: “provided adapter is not valid: borg”**  
  Ensure the router registers `case backup.BorgBackupAdapter` for both create and restore paths.

- **“unsupported compression type” on create**  
  Your Borg lacks `zstd`. The adapter falls back to `lz4`. Consider updating `borgbackup`.

- **Files restored with 1970 timestamp**  
  Fixed by parsing Borg timestamps with and without timezone/fractional seconds.

- **Wings restarts during restore**  
  Restore is fully streaming (no large buffers). If it still happens, check OOM:  
  `dmesg | egrep -i 'killed process|out of memory|oom' | tail -n 20`

---

## 🤝 Contributing

- Open an **issue** with reproducible steps, logs, and Borg/Wings versions.
- Submit **pull requests** with clear descriptions and manual test notes (journalctl and relevant borg output).
- All contributions are welcome: docs, bug fixes, refactors, DX improvements, etc.

---

## 🙇 Credits

- Upstream: **Pterodactyl** (Panel & Wings) — MIT License.
- This fork adds **Borg** backup support to **Wings**.

---

## 🗺️ Roadmap

- [ ] Automated tests for create/restore flows.
- [ ] Optional remote repositories (SSH) and external key management.
- [ ] Optional telemetry/metrics for backup progress.
- [ ] Helper CLI for manual tasks (list/mount/verify).

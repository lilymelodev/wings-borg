// server/backup/backup_borg.go
package backup

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"emperror.dev/errors"
	"github.com/apex/log"

	"github.com/pterodactyl/wings/remote"
	"github.com/pterodactyl/wings/server/filesystem"
)

//
// ========= ENV =========
// WINGS_BORG_REPOSITORY_ROOT (default: /var/lib/pterodactyl/backups/borg)
// WINGS_BORG_PASSPHRASE_DIR  (default: /etc/pterodactyl/borg)
// WINGS_BORG_ENCRYPTION_MODE (default: repokey-blake2)
//

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

type borgSettings struct {
	RepoRoot    string
	PassDir     string
	EncryptMode string
}

func loadBorgSettings() borgSettings {
	return borgSettings{
		RepoRoot:    envOr("WINGS_BORG_REPOSITORY_ROOT", "/var/lib/pterodactyl/backups/borg"),
		PassDir:     envOr("WINGS_BORG_PASSPHRASE_DIR", "/etc/pterodactyl/borg"),
		EncryptMode: envOr("WINGS_BORG_ENCRYPTION_MODE", "repokey-blake2"),
	}
}

type BorgBackup struct {
	Backup
	serverUUID string
	logContext map[string]interface{}
}

func NewBorg(client remote.Client, backupUUID string, ignore string) *BorgBackup {
	return &BorgBackup{
		Backup: Backup{
			client:  client,
			Uuid:    backupUUID,
			Ignore:  ignore,
			adapter: BorgBackupAdapter,
		},
	}
}

func (b *BorgBackup) WithLogContext(ctx map[string]interface{}) {
	if ctx == nil {
		b.logContext = map[string]interface{}{}
	} else {
		 b.logContext = ctx
	}
}

func (b *BorgBackup) log() *log.Entry {
	l := log.WithField("subsystem", "backups:borg").WithField("backup_uuid", b.Uuid)
	for k, v := range b.logContext {
		l = l.WithField(k, v)
	}
	return l
}

func (b *BorgBackup) Path() string    { return b.Uuid }
func (b *BorgBackup) Ignored() string { return b.Ignore }

// ---------- Generate ----------
func (b *BorgBackup) Generate(ctx context.Context, fsys *filesystem.Filesystem, ignore string) (*ArchiveDetails, error) {
	b.serverUUID = inferServerUUIDFromFS(fsys)
	repo, passfile := borgPathsFor(b.serverUUID)

	if err := b.ensurePassphrase(passfile); err != nil {
		return nil, err
	}
	if err := b.ensureRepo(ctx, repo, passfile); err != nil {
		return nil, err
	}

	exclFile, err := b.buildExcludeFile(ignore)
	if err != nil {
		return nil, err
	}
	defer os.Remove(exclFile)

	dest := fmt.Sprintf("%s::%s", repo, b.Uuid)

	args := []string{
		"create", "--stats", "--json",
		"--compression", "zstd,3",
		"--checkpoint-interval", "300",
		"--exclude-caches",
		"--exclude-from", exclFile,
		dest,
		".",
	}
	if _, errb, err := b.execBorgDir(ctx, args, passFromFile(passfile), fsys.Path()); err != nil {
		if strings.Contains(string(errb), "unsupported compression type") ||
			strings.Contains(string(errb), "Unknown compression") {
			b.log().Warn("zstd no soportado por borg; reintentando con lz4")
			args2 := []string{
				"create", "--stats", "--json",
				"--compression", "lz4",
				"--checkpoint-interval", "300",
				"--exclude-caches",
				"--exclude-from", exclFile,
				dest,
				".",
			}
			if _, _, err2 := b.execBorgDir(ctx, args2, passFromFile(passfile), fsys.Path()); err2 != nil {
				return nil, errors.WrapIf(err2, "borg create failed (lz4)")
			}
		} else {
			return nil, errors.WrapIf(err, "borg create failed")
		}
	}

	ad := ArchiveDetails{
		ChecksumType: "borg",
		Checksum:     b.Uuid,
	}
	if sz, err := b.Size(); err == nil {
		ad.Size = sz
	}
	return &ad, nil
}

// ---------- Restore ----------
func (b *BorgBackup) Restore(ctx context.Context, _ io.Reader, cb RestoreCallback) error {
	repo, passfile, err := b.resolveRepoAndPass()
	if err != nil {
		return err
	}
	list, err := b.listFiles(ctx, repo, b.Uuid, passFromFile(passfile))
	if err != nil {
		return err
	}
	repoArchive := fmt.Sprintf("%s::%s", repo, b.Uuid)

	for _, it := range list {
		if normalizeItemType(it.Type) != "f" {
			continue
		}
		rel := relativizeForServerRoot(it.Path, b.serverUUID)
		if rel == "" {
			continue
		}

		args := []string{"extract", "--stdout", repoArchive, it.Path}
		cmd := exec.CommandContext(ctx, "borg", args...)
		cmd.Env = append(os.Environ(),
			"BORG_PASSPHRASE="+strings.TrimSpace(string(passFromFile(passfile))),
			"BORG_RELOCATED_REPO_ACCESS_IS_OK=yes",
		)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return errors.WrapIf(err, "borg extract: stdout pipe failed")
		}
		var errb bytes.Buffer
		cmd.Stderr = &errb

		if err := cmd.Start(); err != nil {
			return errors.WrapIf(err, "borg extract: start failed")
		}

		mode := it.Mode
		if mode == 0 {
			mode = 0o644
		}
		info := borgFileInfo{
			name:  rel,
			size:  it.Size,
			mode:  os.FileMode(mode),
			mtime: time.Unix(it.Mtime, 0),
		}

		cbErr := cb(rel, info, stdout)
		_ = stdout.Close()
		waitErr := cmd.Wait()

		if cbErr != nil {
			return cbErr
		}
		if waitErr != nil {
			return errors.WrapIf(waitErr, "borg extract failed: "+errb.String())
		}
	}

	return nil
}

// ---------- Remove / Checksum / Size ----------
func (b *BorgBackup) Remove() error {
	repo, passfile, err := b.resolveRepoAndPass()
	if err != nil {
		return err
	}
	_, _, err = b.execBorg(context.Background(), []string{"delete", "--log-json", fmt.Sprintf("%s::%s", repo, b.Uuid)}, passFromFile(passfile))
	return err
}

func (b *BorgBackup) Checksum() ([]byte, error) {
	repo, passfile, err := b.resolveRepoAndPass()
	if err != nil {
		return nil, err
	}
	id, err := b.archiveID(context.Background(), repo, b.Uuid, passFromFile(passfile))
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum([]byte(id))
	out := make([]byte, len(sum))
	copy(out, sum[:])
	return out, nil
}

func (b *BorgBackup) Size() (int64, error) {
	repo, passfile, err := b.resolveRepoAndPass()
	if err != nil {
		return 0, err
	}
	info, err := b.archiveInfo(context.Background(), repo, b.Uuid, passFromFile(passfile))
	if err != nil {
		return 0, err
	}
	if info.Archive.DeduplicatedSize > 0 {
		return info.Archive.DeduplicatedSize, nil
	}
	return info.Archive.CompressedSize, nil
}

// ============================= Helpers =============================
func inferServerUUIDFromFS(fsys *filesystem.Filesystem) string {
	if fsys == nil {
		return ""
	}
	root := strings.TrimRight(fsys.Path(), string(filepath.Separator))
	return filepath.Base(root)
}

func borgPathsFor(serverUUID string) (repo, passfile string) {
	cfg := loadBorgSettings()
	if serverUUID == "" {
		serverUUID = "_unknown_server_"
	}
	repo = filepath.Join(cfg.RepoRoot, serverUUID)
	passfile = filepath.Join(cfg.PassDir, serverUUID+".pass")
	return
}

func (b *BorgBackup) resolveRepoAndPass() (string, string, error) {
	cfg := loadBorgSettings()
	if b.serverUUID != "" {
		repo, pass := borgPathsFor(b.serverUUID)
		return repo, pass, nil
	}
	entries, err := os.ReadDir(cfg.RepoRoot)
	if err != nil {
		return "", "", err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		server := e.Name()
		repo, pass := borgPathsFor(server)
		if _, _, err := b.execBorg(context.Background(), []string{"info", fmt.Sprintf("%s::%s", repo, b.Uuid)}, passFromFile(pass)); err == nil {
			b.serverUUID = server
			return repo, pass, nil
		}
	}
	return "", "", errors.New("borg: no se encontró repo para este backup uuid")
}

func passFromFile(path string) []byte {
	b, _ := os.ReadFile(path)
	return b
}

func (b *BorgBackup) ensurePassphrase(passfile string) error {
	if err := os.MkdirAll(filepath.Dir(passfile), 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(passfile); os.IsNotExist(err) {
		pass := randomPass(64)
		if err := os.WriteFile(passfile, []byte(pass), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func (b *BorgBackup) ensureRepo(ctx context.Context, repo, passfile string) error {
	if _, _, err := b.execBorg(ctx, []string{"info", repo}, passFromFile(passfile)); err == nil {
		return nil
	}
	_, _, err := b.execBorg(ctx, []string{"init", "--encryption", loadBorgSettings().EncryptMode, repo}, passFromFile(passfile))
	return err
}

func (b *BorgBackup) buildExcludeFile(ignore string) (string, error) {
	f, err := os.CreateTemp("", "wings-borg-exclude-*.txt")
	if err != nil {
		return "", err
	}
	defer f.Close()
	var lines []string
	if ignore != "" {
		lines = append(lines, strings.Split(ignore, "\n")...)
	}
	lines = append(lines, ".pteroignore", ".git", ".cache")
	_, _ = f.WriteString(strings.Join(lines, "\n"))
	return f.Name(), nil
}

func (b *BorgBackup) execBorg(ctx context.Context, args []string, pass []byte) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, "borg", args...)
	if len(pass) > 0 {
		cmd.Env = append(os.Environ(),
			"BORG_PASSPHRASE="+strings.TrimSpace(string(pass)),
			"BORG_RELOCATED_REPO_ACCESS_IS_OK=yes",
		)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.Bytes(), errb.Bytes(), errors.WrapIf(err, fmt.Sprintf("borg %s failed: %s", strings.Join(args, " "), errb.String()))
	}
	return out.Bytes(), errb.Bytes(), nil
}

func (b *BorgBackup) execBorgDir(ctx context.Context, args []string, pass []byte, dir string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, "borg", args...)
	cmd.Dir = dir
	if len(pass) > 0 {
		cmd.Env = append(os.Environ(),
			"BORG_PASSPHRASE="+strings.TrimSpace(string(pass)),
			"BORG_RELOCATED_REPO_ACCESS_IS_OK=yes",
		)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.Bytes(), errb.Bytes(), errors.WrapIf(err, fmt.Sprintf("borg %s failed: %s", strings.Join(args, " "), errb.String()))
	}
	return out.Bytes(), errb.Bytes(), nil
}

func (b *BorgBackup) archiveID(ctx context.Context, repo, backupUUID string, pass []byte) (string, error) {
	info, err := b.archiveInfo(ctx, repo, backupUUID, pass)
	if err != nil {
		return "", err
	}
	return info.Archive.ID, nil
}

type borgInfo struct {
	Archive struct {
		ID               string  `json:"id"`
		Name             string  `json:"name"`
		Duration         float64 `json:"duration"`
		CompressedSize   int64   `json:"compressed_size"`
		DeduplicatedSize int64   `json:"deduplicated_size"`
	} `json:"archive"`
}

type borgList struct {
	Items []struct {
		Path  string `json:"path"`
		Type  string `json:"type"`
		Size  int64  `json:"size"`
		Mode  int    `json:"mode"`
		Mtime int64  `json:"mtime"`
	} `json:"items"`
}

func (b *BorgBackup) archiveInfo(ctx context.Context, repo, backupUUID string, pass []byte) (*borgInfo, error) {
	out, _, err := b.execBorg(ctx, []string{"info", "--json", fmt.Sprintf("%s::%s", repo, backupUUID)}, pass)
	if err != nil {
		return nil, err
	}
	var bi borgInfo
	if e := json.Unmarshal(out, &bi); e != nil {
		return nil, e
	}
	return &bi, nil
}

type fileEntry struct {
	Path  string
	Type  string
	Size  int64
	Mode  int
	Mtime int64
}

func normalizeItemType(t string) string {
	switch t {
	case "-", "file", "f":
		return "f"
	case "d", "dir", "directory":
		return "d"
	case "l", "link", "symlink":
		return "l"
	case "h", "hardlink":
		return "h"
	default:
		return t
	}
}

// Lista contenido del archive (json-lines con fallback a texto)
func (b *BorgBackup) listFiles(ctx context.Context, repo, backupUUID string, pass []byte) ([]fileEntry, error) {
	repoArchive := fmt.Sprintf("%s::%s", repo, backupUUID)

	// JSON lines
	out, _, err := b.execBorg(ctx, []string{"list", "--json-lines", repoArchive}, pass)
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		files := make([]fileEntry, 0, len(lines))
		for _, ln := range lines {
			ln = strings.TrimSpace(ln)
			if ln == "" {
				continue
			}
			var obj map[string]interface{}
			if e := json.Unmarshal([]byte(ln), &obj); e != nil {
				continue
			}
			var fe fileEntry
			if v, ok := obj["path"].(string); ok {
				fe.Path = v
			}
			if v, ok := obj["type"].(string); ok {
				fe.Type = normalizeItemType(v)
			}
			// size
			switch v := obj["size"].(type) {
			case float64:
				fe.Size = int64(v)
			case string:
				if n, e := strconv.ParseInt(v, 10, 64); e == nil {
					fe.Size = n
				}
			}
			// mode: puede venir como "0644" numérico o "-rw-r--r--" string
			if v, ok := obj["mode"].(string); ok && fe.Mode == 0 {
				if m, ok2 := parsePermString(v, fe.Type == "d"); ok2 {
					fe.Mode = m
				}
			} else if vv, ok := obj["mode"].(float64); ok {
				fe.Mode = int(vv)
			}
			// mtime: RFC3339 o epoch
			switch v := obj["mtime"].(type) {
            case string:
            	if ts, ok := parseBorgTimeToUnix(v); ok {
            		fe.Mtime = ts
            	}
            case float64:
            	fe.Mtime = int64(v)
            }
			files = append(files, fe)
		}
		return files, nil
	}

	// Fallback --format
	out2, _, err2 := b.execBorg(ctx, []string{
		"list", "--format", "{type} {mode} {size} {mtime} {path}{NL}", repoArchive,
	}, pass)
	if err2 != nil {
		return nil, err
	}
	files := []fileEntry{}
	for _, ln := range strings.Split(strings.TrimSpace(string(out2)), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		parts := strings.SplitN(ln, " ", 5)
		if len(parts) < 5 {
			continue
		}
		var fe fileEntry
		fe.Type = normalizeItemType(parts[0])
		if n, e := strconv.ParseInt(parts[1], 10, 64); e == nil {
			fe.Mode = int(n)
		} else if m, ok := parsePermString(parts[1], fe.Type == "d"); ok {
			fe.Mode = m
		}
		if n, e := strconv.ParseInt(parts[2], 10, 64); e == nil {
			fe.Size = n
		}
		if n, e := strconv.ParseInt(parts[3], 10, 64); e == nil {
        	fe.Mtime = n
        } else {
        	if ts, ok := parseBorgTimeToUnix(parts[3]); ok {
        		fe.Mtime = ts
        	}
        }
		fe.Path = parts[4]
		files = append(files, fe)
	}
	return files, nil
}

type borgFileInfo struct {
	name  string
	size  int64
	mode  os.FileMode
	mtime time.Time
}

func (fi borgFileInfo) Name() string       { return filepath.Base(fi.name) }
func (fi borgFileInfo) Size() int64        { return fi.size }
func (fi borgFileInfo) Mode() os.FileMode  { return fi.mode }
func (fi borgFileInfo) ModTime() time.Time { return fi.mtime }
func (fi borgFileInfo) IsDir() bool        { return false }
func (fi borgFileInfo) Sys() any           { return nil }

func randomPass(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-+="
	b := make([]byte, n)
	seed := time.Now().UnixNano()
	for i := range b {
		seed = (1103515245*seed + 12345) & 0x7fffffff
		b[i] = letters[int(seed)%len(letters)]
	}
	return string(b)
}

func parsePermString(s string, _ bool) (int, bool) {
	if len(s) < 10 {
		return 0, false
	}
	p := s[1:10]
	if len(p) != 9 {
		return 0, false
	}
	bit := func(c byte, want byte) int {
		if c == want {
			return 1
		}
		return 0
	}
	ur := bit(p[0], 'r')
	uw := bit(p[1], 'w')
	ux := bit(p[2], 'x')
	gr := bit(p[3], 'r')
	gw := bit(p[4], 'w')
	gx := bit(p[5], 'x')
	or := bit(p[6], 'r')
	ow := bit(p[7], 'w')
	ox := bit(p[8], 'x')
	mode := (ur*4+uw*2+ux)*64 + (gr*4+gw*2+gx)*8 + (or*4+ow*2+ox)
	return mode, true
}

func relativizeForServerRoot(p, serverUUID string) string {
	p = filepath.Clean(p)
	p = strings.TrimPrefix(p, "/")
	p = strings.TrimPrefix(p, "./")
	if serverUUID != "" {
		if idx := strings.Index(p, serverUUID); idx >= 0 {
			after := p[idx+len(serverUUID):]
			after = strings.TrimPrefix(after, "/")
			return after
		}
	}
	if strings.HasPrefix(p, "home/container/") {
		return strings.TrimPrefix(p, "home/container/")
	}
	if p == "home/container" {
		return ""
	}
	return p
}

func parseBorgTimeToUnix(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}

	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, true
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return int64(f), true
	}

	layouts := []string{
		time.RFC3339Nano,
		"2006-01-02T15:04:05.999999999Z07:00",
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05.999999",
		"2006-01-02T15:04:05",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.Unix(), true
		}
	}
	
	if !strings.ContainsAny(s, "Z+-") {
		if t, err := time.Parse("2006-01-02T15:04:05.999999999Z07:00", s+"Z"); err == nil {
			return t.Unix(), true
		}
		if t, err := time.Parse(time.RFC3339Nano, s+"Z"); err == nil {
			return t.Unix(), true
		}
	}
	return 0, false
}

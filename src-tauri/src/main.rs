// Prevent an extra console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use regex::Regex;
use serde::Serialize;
use tauri::{AppHandle, Emitter, State};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_opener::OpenerExt;

#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

// ── Scan control ────────────────────────────────────────────────
// One shared byte drives the active scan: 0 = running, 1 = paused, 2 = stopped.
// A fresh Arc is created for every scan and stashed here so the pause/resume/stop
// commands (which run concurrently while `scan` is awaiting) can flip it.
struct ScanControl(Mutex<Option<Arc<AtomicU8>>>);

const RUNNING: u8 = 0;
const PAUSED: u8 = 1;
const STOPPED: u8 = 2;

// ── Clutter rules ───────────────────────────────────────────────
// Each rule matches a directory *name* that holds regenerable output (build
// artifacts, dependency caches, virtual envs). To avoid ever flagging real
// source, ambiguous names (bin, obj, build, dist…) only count when a telltale
// marker file sits next to them (a sibling) or inside them.
struct Rule {
    names: &'static [&'static str], // directory names, lowercase
    label: &'static str,            // shown in the Type column
    sibling_any: &'static [&'static str], // any of these must be a sibling (exact name or "*.ext")
    inside_any: &'static [&'static str],  // any of these must exist inside the candidate
}

const RULES: &[Rule] = &[
    // Always-safe: unambiguous dependency / cache directories.
    Rule { names: &["node_modules"], label: "npm packages", sibling_any: &[], inside_any: &[] },
    // Context-dependent build outputs (need a build-system marker sibling).
    Rule { names: &["target"], label: "Rust build", sibling_any: &["cargo.toml"], inside_any: &[] },
    Rule { names: &["target"], label: "Maven build", sibling_any: &["pom.xml"], inside_any: &[] },
    Rule { names: &["bin", "obj"], label: ".NET build", sibling_any: &["*.csproj", "*.sln", "*.vbproj", "*.fsproj"], inside_any: &[] },
    Rule { names: &["build"], label: "Build output", sibling_any: &["pubspec.yaml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "cmakelists.txt"], inside_any: &[] },
    Rule { names: &["dist", "out"], label: "JS build output", sibling_any: &["package.json"], inside_any: &[] },
    Rule { names: &["pods"], label: "CocoaPods", sibling_any: &["podfile"], inside_any: &[] },
    // Python.
    Rule { names: &["__pycache__"], label: "Python cache", sibling_any: &[], inside_any: &[] },
    Rule { names: &[".pytest_cache"], label: "Pytest cache", sibling_any: &[], inside_any: &[] },
    Rule { names: &[".mypy_cache"], label: "Mypy cache", sibling_any: &[], inside_any: &[] },
    Rule { names: &[".ruff_cache"], label: "Ruff cache", sibling_any: &[], inside_any: &[] },
    Rule { names: &[".tox"], label: "Tox envs", sibling_any: &[], inside_any: &[] },
    Rule { names: &[".venv"], label: "Python venv", sibling_any: &[], inside_any: &[] },
    Rule { names: &["venv", "env"], label: "Python venv", sibling_any: &[], inside_any: &["pyvenv.cfg"] },
    // JS / web framework caches & build dirs.
    Rule { names: &[".next"], label: "Next.js build", sibling_any: &[], inside_any: &[] },
    Rule { names: &[".nuxt"], label: "Nuxt build", sibling_any: &[], inside_any: &[] },
    Rule { names: &[".svelte-kit"], label: "SvelteKit build", sibling_any: &[], inside_any: &[] },
    Rule { names: &[".angular"], label: "Angular cache", sibling_any: &[], inside_any: &[] },
    Rule { names: &[".turbo"], label: "Turbo cache", sibling_any: &[], inside_any: &[] },
    Rule { names: &[".parcel-cache"], label: "Parcel cache", sibling_any: &[], inside_any: &[] },
    Rule { names: &[".vite"], label: "Vite cache", sibling_any: &[], inside_any: &[] },
    Rule { names: &[".expo"], label: "Expo cache", sibling_any: &[], inside_any: &[] },
    // Native / mobile / infra.
    Rule { names: &[".gradle"], label: "Gradle cache", sibling_any: &[], inside_any: &[] },
    Rule { names: &[".dart_tool"], label: "Dart tool cache", sibling_any: &[], inside_any: &[] },
    Rule { names: &[".terraform"], label: "Terraform cache", sibling_any: &[], inside_any: &[] },
    Rule { names: &[".vs"], label: "Visual Studio cache", sibling_any: &[], inside_any: &[] },
    Rule { names: &["deriveddata"], label: "Xcode DerivedData", sibling_any: &[], inside_any: &[] },
    // Go / PHP vendored dependencies (regenerable via `go mod vendor` / `composer install`).
    Rule { names: &["vendor"], label: "Go vendor", sibling_any: &["go.mod"], inside_any: &["modules.txt"] },
    Rule { names: &["vendor"], label: "Composer packages", sibling_any: &["composer.json"], inside_any: &[] },
    // Swift Package Manager.
    Rule { names: &[".build"], label: "Swift build", sibling_any: &["package.swift"], inside_any: &[] },
    // Elixir.
    Rule { names: &["_build"], label: "Elixir build", sibling_any: &["mix.exs"], inside_any: &[] },
    Rule { names: &["deps"], label: "Elixir deps", sibling_any: &["mix.exs"], inside_any: &[] },
    // Haskell.
    Rule { names: &["dist-newstyle"], label: "Haskell build", sibling_any: &[], inside_any: &[] },
    Rule { names: &[".stack-work"], label: "Haskell build", sibling_any: &[], inside_any: &[] },
    // Zig.
    Rule { names: &["zig-cache", "zig-out"], label: "Zig build", sibling_any: &[], inside_any: &[] },
    // C / C++ out-of-source builds (CLion).
    Rule { names: &["cmake-build-debug", "cmake-build-release"], label: "CMake build", sibling_any: &[], inside_any: &[] },
    // Unity (large regenerable caches; gated on a Unity project marker).
    Rule { names: &["library", "temp"], label: "Unity cache", sibling_any: &["projectsettings"], inside_any: &[] },
    // Unreal Engine (gated on a .uproject; leaves Saved/ alone since it can hold autosaves & logs).
    Rule { names: &["intermediate", "binaries", "deriveddatacache"], label: "Unreal build", sibling_any: &["*.uproject"], inside_any: &[] },
    // Notebooks / Android NDK / monorepo & framework caches.
    Rule { names: &[".ipynb_checkpoints"], label: "Jupyter checkpoints", sibling_any: &[], inside_any: &[] },
    Rule { names: &[".cxx"], label: "Android NDK cache", sibling_any: &[], inside_any: &[] },
    Rule { names: &[".nx"], label: "Nx cache", sibling_any: &[], inside_any: &[] },
    Rule { names: &[".astro"], label: "Astro cache", sibling_any: &[], inside_any: &[] },
    Rule { names: &[".docusaurus"], label: "Docusaurus cache", sibling_any: &[], inside_any: &[] },
];

// True if any pattern matches a name in `names` (exact, or "*.ext" suffix).
fn any_matches(patterns: &[&str], names: &HashSet<String>) -> bool {
    patterns.iter().any(|pat| {
        if let Some(ext) = pat.strip_prefix("*.") {
            let suffix = format!(".{}", ext);
            names.iter().any(|n| n.ends_with(suffix.as_str()))
        } else {
            names.contains(*pat)
        }
    })
}

// If this directory is regenerable clutter, return its category label.
// `siblings` are the lowercased names sitting alongside `candidate`.
fn match_rule(dname: &str, siblings: &HashSet<String>, candidate: &Path) -> Option<&'static str> {
    for rule in RULES {
        if !rule.names.iter().any(|n| *n == dname) {
            continue;
        }
        if !rule.sibling_any.is_empty() && !any_matches(rule.sibling_any, siblings) {
            continue;
        }
        if !rule.inside_any.is_empty() {
            let inside: HashSet<String> = match fs::read_dir(candidate) {
                Ok(rd) => rd
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().to_lowercase())
                    .collect(),
                Err(_) => HashSet::new(),
            };
            if !any_matches(rule.inside_any, &inside) {
                continue;
            }
        }
        return Some(rule.label);
    }
    None
}

// ── Payloads ────────────────────────────────────────────────────
#[derive(Clone, Serialize)]
struct Item {
    category: String,
    size: u64,
    path: String,
    modified: Option<i64>,
}

#[derive(Serialize)]
struct ScanResult {
    items: Vec<Item>,
    scanned: u64,
    found: u64,
    bytes: u64,
}

#[derive(Clone, Serialize)]
struct Progress {
    scanned: u64,
    found: u64,
    bytes: u64,
}

#[derive(Clone, Serialize)]
struct DeleteProgress {
    done: u64,
    total: u64,
}

#[derive(Serialize)]
struct DeleteResult {
    path: String,
    ok: bool,
    error: Option<String>,
}

#[derive(Serialize)]
struct ExportResult {
    ok: bool,
    error: Option<String>,
}

// ── Walk state ──────────────────────────────────────────────────
struct ScanCtx {
    control: Arc<AtomicU8>,
    min_bytes: u64,
    items: Vec<Item>,
    scanned: u64, // files + folders visited (drives the progress ticker)
    found: u64,   // clutter items recorded
    bytes: u64,   // total reclaimable bytes recorded
    app: AppHandle,
    use_git: bool,       // also clear whatever each repo's .gitignore marks as throwaway
    git_available: bool, // git found on PATH (git mode is a no-op without it)
    seen: HashSet<String>, // absolute paths (lowercased) already recorded, to dedupe
    exclude: Vec<String>,  // user's skip list: file endings ("msix"/".msix") or names (".claude"/"node_modules")
}

impl ScanCtx {
    fn excluded(&self, path: &Path) -> bool {
        is_excluded(&self.exclude, path)
    }
}

// True if this item matches the user's exclude list. Matches a whole name
// (node_modules, .claude) or a file ending (msix -> anything.msix).
fn is_excluded(exclude: &[String], path: &Path) -> bool {
    if exclude.is_empty() {
        return false;
    }
    let leaf = match path.file_name() {
        Some(n) => n.to_string_lossy().to_lowercase(),
        None => return false,
    };
    // Lowercased path parts, so a dot-folder token also hides files inside it.
    let parts: Vec<String> = path
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s.to_string_lossy().to_lowercase()),
            _ => None,
        })
        .collect();
    exclude.iter().any(|t| {
        if leaf == *t {
            return true;
        }
        let bare = t.trim_start_matches('.');
        if !bare.is_empty() && leaf.ends_with(&format!(".{}", bare)) {
            return true;
        }
        // Dot-folder tokens (.claude, .vscode, .idea) hide everything inside that
        // folder too. Restricted to dot tokens so a plain "msix" never wipes the
        // contents of a folder literally named msix.
        t.starts_with('.') && parts.iter().any(|p| p == t)
    })
}

impl ScanCtx {
    // Blocks while paused; returns false once a stop is requested.
    fn check(&self) -> bool {
        loop {
            match self.control.load(Ordering::Relaxed) {
                PAUSED => std::thread::sleep(Duration::from_millis(150)),
                STOPPED => return false,
                _ => return true,
            }
        }
    }

    fn report(&self, every: u64) {
        if self.scanned % every == 0 {
            let _ = self.app.emit(
                "scan-progress",
                Progress {
                    scanned: self.scanned,
                    found: self.found,
                    bytes: self.bytes,
                },
            );
        }
    }

    fn record(&mut self, category: &str, size: u64, path: &Path, modified: Option<i64>) {
        self.found += 1;
        self.bytes += size;
        self.items.push(Item {
            category: category.to_string(),
            size,
            path: path.to_string_lossy().into_owned(),
            modified,
        });
    }

    // First time a path is offered -> true (and marks it). Already offered -> false.
    // Stops git-ignore discovery and the name-rules from double-counting a folder.
    // Slashes are normalized so a git path (a/b) and a walk path (a\b) match.
    fn seen_key(path: &Path) -> String {
        path.to_string_lossy().to_lowercase().replace('\\', "/")
    }
    fn claim(&mut self, path: &Path) -> bool {
        self.seen.insert(Self::seen_key(path))
    }
    fn is_claimed(&self, path: &Path) -> bool {
        self.seen.contains(&Self::seen_key(path))
    }
}

// Skip symlinks and Windows junctions / reparse points so the walk can't loop
// forever through self-referential directories.
fn is_reparse(md: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        md.file_type().is_symlink()
    }
}

// Last-modified time as Unix epoch milliseconds, or None if unavailable.
fn mtime_millis(md: &fs::Metadata) -> Option<i64> {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
}

// A filename that looks like a credential/secret a developer keeps on purpose.
// Errs toward caution (a false positive just leaves a file alone), but still avoids
// broad substring matching that would flag innocent files inside packages.
fn looks_secret(name_lower: &str) -> bool {
    // .env in any form: .env, .env.local, prod.env
    if name_lower == ".env" || name_lower.starts_with(".env.") || name_lower.ends_with(".env") {
        return true;
    }
    const EXACT: &[&str] = &[
        ".npmrc", ".netrc", ".pgpass", ".htpasswd", ".git-credentials", ".dockercfg",
        "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
        "key.properties", "keystore.properties", "signing.properties", "sentry.properties",
        "google-services.json", "googleservice-info.plist",
        "serviceaccount.json", "service-account.json", "gha-creds.json",
    ];
    if EXACT.contains(&name_lower) {
        return true;
    }
    const EXT: &[&str] = &[
        ".pem", ".key", ".pfx", ".p12", ".pkcs12", ".keystore", ".jks", ".ppk",
        ".asc", ".gpg", ".p8", ".mobileprovision", ".cer", ".der",
    ];
    if EXT.iter().any(|e| name_lower.ends_with(e)) {
        return true;
    }
    // Filename stem (before the first dot) that plainly denotes secrets, e.g.
    // secrets.dart, secret.js, credentials.yaml - but NOT secretbox.wasm.
    let stem = name_lower.split('.').next().unwrap_or(name_lower);
    matches!(
        stem,
        "secret" | "secrets" | "credential" | "credentials" | "apikey" | "apikeys"
    )
}

// Total bytes under `dir`, recursively. Honors pause/stop and ticks progress.
fn dir_size(ctx: &mut ScanCtx, dir: &Path) -> u64 {
    let mut total: u64 = 0;
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return 0,
    };
    for entry in entries {
        if !ctx.check() {
            return total;
        }
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        let md = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if is_reparse(&md) {
            continue;
        }
        if md.is_dir() {
            total += dir_size(ctx, &path);
        } else if md.is_file() {
            total += md.len();
            ctx.scanned += 1;
            ctx.report(4000);
        }
    }
    total
}

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

// A git Command that never flashes a console window on Windows.
fn git_command() -> std::process::Command {
    let mut c = std::process::Command::new("git");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(CREATE_NO_WINDOW);
    }
    c
}

fn git_is_available() -> bool {
    git_command()
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// Ask a git repo what it ignores (untracked + ignored), i.e. everything the repo
// itself treats as throwaway. Returns every ignored directory and loose ignored
// file. Nothing is silently filtered out - the user decides what to skip via the
// exclude list.
fn git_ignored_paths(repo: &Path) -> Vec<std::path::PathBuf> {
    let repo_str = match repo.to_str() {
        Some(s) => s,
        None => return Vec::new(),
    };
    let output = match git_command()
        .args([
            "-C",
            repo_str,
            "-c",
            "core.quotepath=false",
            "ls-files",
            "--others",
            "--ignored",
            "--exclude-standard",
            "--directory",
        ])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    parse_ignored_paths(&text, repo)
}

// Turn `git ls-files ... --directory` output into absolute paths. Every ignored
// directory (trailing slash) and every loose ignored file is returned as-is; the
// user's exclude list is the only thing that removes anything.
fn parse_ignored_paths(text: &str, repo: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let rel = line.strip_suffix('/').unwrap_or(line);
        if rel.is_empty() {
            continue;
        }
        out.push(repo.join(rel));
    }
    out
}

// Lowercased names of the entries directly inside `dir` (for marker checks).
fn dir_entry_names(dir: &Path) -> HashSet<String> {
    match fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_lowercase())
            .collect(),
        Err(_) => HashSet::new(),
    }
}

// Best label for a git-ignored directory: reuse the precise ecosystem label when
// the folder is recognizable, otherwise say plainly it came from .gitignore.
fn label_for_ignored(dir: &Path) -> &'static str {
    let name = dir
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let siblings = dir.parent().map(dir_entry_names).unwrap_or_default();
    match_rule(&name, &siblings, dir).unwrap_or("Ignored (.gitignore)")
}

// Walk the tree looking for clutter directories. When one is found we size it
// and record it, but do NOT descend into it (no double counting, and much
// faster since the giant regenerable trees are pruned from the search).
fn walk(ctx: &mut ScanCtx, dir: &Path) -> bool {
    if !ctx.check() {
        return false;
    }

    // If this is a git repo, let the repo's own .gitignore tell us what is
    // throwaway. This covers any ecosystem, even ones the name-rules never heard
    // of. Runs once per repo root; nested matches are deduped against the rules.
    if ctx.use_git && ctx.git_available && dir.join(".git").exists() {
        for ignored in git_ignored_paths(dir) {
            if !ctx.check() {
                return false;
            }
            if !ctx.claim(&ignored) {
                continue;
            }
            let md = match fs::symlink_metadata(&ignored) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if is_reparse(&md) {
                continue;
            }
            if ctx.excluded(&ignored) {
                continue; // only the user's exclude list removes anything
            }
            if md.is_dir() {
                let label = label_for_ignored(&ignored);
                let size = dir_size(ctx, &ignored);
                ctx.scanned += 1;
                ctx.report(1);
                if size >= ctx.min_bytes {
                    ctx.record(label, size, &ignored, mtime_millis(&md));
                }
            } else if md.is_file() {
                let size = md.len();
                ctx.scanned += 1;
                ctx.report(1);
                if size >= ctx.min_bytes {
                    ctx.record("Ignored (.gitignore)", size, &ignored, mtime_millis(&md));
                }
            }
        }
    }

    let entries: Vec<fs::DirEntry> = match fs::read_dir(dir) {
        Ok(rd) => rd.filter_map(|e| e.ok()).collect(),
        Err(_) => return true,
    };
    // Names present in this directory, for sibling-marker checks.
    let siblings: HashSet<String> = entries
        .iter()
        .map(|e| e.file_name().to_string_lossy().to_lowercase())
        .collect();

    for entry in &entries {
        if !ctx.check() {
            return false;
        }
        let path = entry.path();
        let md = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if is_reparse(&md) {
            continue;
        }
        if md.is_dir() {
            if ctx.is_claimed(&path) {
                continue; // already recorded via git-ignore discovery
            }
            let dname = entry.file_name().to_string_lossy().to_lowercase();
            if let Some(label) = match_rule(&dname, &siblings, &path) {
                ctx.claim(&path);
                if ctx.excluded(&path) {
                    continue; // user chose to skip this
                }
                let size = dir_size(ctx, &path);
                ctx.scanned += 1;
                ctx.report(1);
                if size >= ctx.min_bytes {
                    ctx.record(label, size, &path, mtime_millis(&md));
                }
            } else {
                ctx.scanned += 1;
                if !walk(ctx, &path) {
                    return false;
                }
            }
        }
    }
    true
}

fn run_scan(
    app: AppHandle,
    control: Arc<AtomicU8>,
    root: String,
    min_bytes: u64,
    use_git: bool,
    exclude: Vec<String>,
) -> ScanResult {
    let git_available = use_git && git_is_available();
    // Keep the user's tokens as typed (lowercased/trimmed); matching handles both
    // "msix"/".msix" endings and whole names like ".claude" or "node_modules".
    let exclude: Vec<String> = exclude
        .into_iter()
        .map(|e| e.trim().to_lowercase())
        .filter(|e| !e.is_empty())
        .collect();
    let mut ctx = ScanCtx {
        control,
        min_bytes,
        items: Vec::new(),
        scanned: 0,
        found: 0,
        bytes: 0,
        app,
        use_git,
        git_available,
        seen: HashSet::new(),
        exclude,
    };

    let root_path = Path::new(&root);
    let _ = walk(&mut ctx, root_path);

    let mut items = ctx.items;
    items.sort_by(|a, b| b.size.cmp(&a.size));

    ScanResult {
        items,
        scanned: ctx.scanned,
        found: ctx.found,
        bytes: ctx.bytes,
    }
}

// ── Commands ────────────────────────────────────────────────────
#[tauri::command]
async fn scan(
    app: AppHandle,
    control: State<'_, ScanControl>,
    root: String,
    floor: u64,
    git: bool,
    exclude: Vec<String>,
) -> Result<ScanResult, String> {
    if root.trim().is_empty() || !Path::new(&root).is_dir() {
        return Err("That folder could not be found.".into());
    }
    let ctrl = Arc::new(AtomicU8::new(RUNNING));
    {
        *control.0.lock().unwrap() = Some(ctrl.clone());
    }
    let app2 = app.clone();
    let result =
        tauri::async_runtime::spawn_blocking(move || run_scan(app2, ctrl, root, floor, git, exclude))
            .await
            .map_err(|e| e.to_string())?;
    Ok(result)
}

#[tauri::command]
fn stop_scan(control: State<'_, ScanControl>) {
    if let Some(c) = control.0.lock().unwrap().as_ref() {
        c.store(STOPPED, Ordering::Relaxed);
    }
}

#[tauri::command]
fn pause_scan(control: State<'_, ScanControl>) {
    if let Some(c) = control.0.lock().unwrap().as_ref() {
        c.store(PAUSED, Ordering::Relaxed);
    }
}

#[tauri::command]
fn resume_scan(control: State<'_, ScanControl>) {
    if let Some(c) = control.0.lock().unwrap().as_ref() {
        c.store(RUNNING, Ordering::Relaxed);
    }
}

#[tauri::command]
fn path_exists(path: String) -> bool {
    Path::new(&path).is_dir()
}

// Remove the given paths. `permanent` = delete for good (frees space now, no undo);
// otherwise move to the Recycle Bin (recoverable, but space is only reclaimed once
// the bin is emptied). Runs off the UI thread and reports progress so the window
// never appears frozen while a multi-GB folder is being removed. A path is counted
// as a success when it is actually gone from disk afterward.
#[tauri::command]
async fn delete_files(
    app: AppHandle,
    paths: Vec<String>,
    permanent: bool,
) -> Result<Vec<DeleteResult>, String> {
    let app2 = app.clone();
    let results = tauri::async_runtime::spawn_blocking(move || {
        let total = paths.len() as u64;
        let mut out: Vec<DeleteResult> = Vec::with_capacity(paths.len());
        for (i, p) in paths.into_iter().enumerate() {
            let path = Path::new(&p);
            let op_err: Option<String> = if permanent {
                let r = if path.is_dir() {
                    fs::remove_dir_all(path)
                } else {
                    fs::remove_file(path)
                };
                r.err().map(|e| e.to_string())
            } else {
                trash::delete(&p).err().map(|e| e.to_string())
            };
            // The goal is that the folder is gone. If it is gone we call it a win,
            // even if the OS returned a "not found" style error (already deleted).
            let gone = !path.exists();
            let error = if gone {
                None
            } else {
                Some(op_err.unwrap_or_else(|| "Could not remove this item.".to_string()))
            };
            out.push(DeleteResult {
                path: p,
                ok: gone,
                error,
            });
            let _ = app2.emit(
                "delete-progress",
                DeleteProgress {
                    done: i as u64 + 1,
                    total,
                },
            );
        }
        out
    })
    .await
    .map_err(|e| e.to_string())?;
    Ok(results)
}

#[tauri::command]
fn show_in_explorer(app: AppHandle, path: String) -> Result<(), String> {
    app.opener()
        .reveal_item_in_dir(&path)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn open_external(app: AppHandle, url: String) -> Result<(), String> {
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn pick_folder(app: AppHandle) -> Result<Option<String>, String> {
    let picked = tauri::async_runtime::spawn_blocking(move || {
        app.dialog().file().blocking_pick_folder()
    })
    .await
    .map_err(|e| e.to_string())?;
    Ok(picked
        .and_then(|fp| fp.into_path().ok())
        .map(|p| p.to_string_lossy().into_owned()))
}

#[tauri::command]
fn set_window_theme(window: tauri::Window, theme: String) -> Result<(), String> {
    let t = if theme == "light" {
        tauri::Theme::Light
    } else {
        tauri::Theme::Dark
    };
    window.set_theme(Some(t)).map_err(|e| e.to_string())
}

#[tauri::command]
fn copy_text(text: String) -> Result<(), String> {
    let mut clipboard = arboard::Clipboard::new().map_err(|e| e.to_string())?;
    clipboard.set_text(text).map_err(|e| e.to_string())
}

fn esc_csv(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn build_csv(headers: &[String], rows: &[Vec<String>]) -> String {
    let mut lines: Vec<String> = Vec::with_capacity(rows.len() + 1);
    lines.push(
        headers
            .iter()
            .map(|h| esc_csv(h))
            .collect::<Vec<_>>()
            .join(","),
    );
    for row in rows {
        lines.push(row.iter().map(|c| esc_csv(c)).collect::<Vec<_>>().join(","));
    }
    lines.join("\r\n")
}

fn build_txt(headers: &[String], rows: &[Vec<String>]) -> String {
    let cols = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate().take(cols) {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let pad = |s: &str, w: usize| -> String {
        let mut out = String::from(s);
        for _ in s.chars().count()..w {
            out.push(' ');
        }
        out
    };
    let mut lines: Vec<String> = Vec::with_capacity(rows.len() + 2);
    lines.push(
        headers
            .iter()
            .enumerate()
            .map(|(i, h)| pad(h, widths[i]))
            .collect::<Vec<_>>()
            .join("  "),
    );
    lines.push(
        widths
            .iter()
            .map(|w| "-".repeat(*w))
            .collect::<Vec<_>>()
            .join("  "),
    );
    for row in rows {
        lines.push(
            (0..cols)
                .map(|i| pad(row.get(i).map(|s| s.as_str()).unwrap_or(""), widths[i]))
                .collect::<Vec<_>>()
                .join("  "),
        );
    }
    lines.join("\r\n")
}

#[tauri::command]
async fn export_data(
    app: AppHandle,
    format: String,
    name: String,
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
) -> Result<ExportResult, String> {
    let content = if format == "csv" {
        build_csv(&headers, &rows)
    } else {
        build_txt(&headers, &rows)
    };
    let (filter_name, ext): (&str, &str) = if format == "csv" {
        ("CSV Files", "csv")
    } else {
        ("Text Files", "txt")
    };

    let app2 = app.clone();
    let picked = tauri::async_runtime::spawn_blocking(move || {
        app2.dialog()
            .file()
            .add_filter(filter_name, &[ext])
            .set_file_name(name)
            .set_title("Export Data")
            .blocking_save_file()
    })
    .await
    .map_err(|e| e.to_string())?;

    match picked {
        Some(file_path) => {
            let path = file_path.into_path().map_err(|e| e.to_string())?;
            // UTF-8 BOM so Excel reads accents correctly, matching the original.
            let mut data = String::from("\u{feff}");
            data.push_str(&content);
            match fs::write(&path, data) {
                Ok(_) => Ok(ExportResult {
                    ok: true,
                    error: None,
                }),
                Err(e) => Ok(ExportResult {
                    ok: false,
                    error: Some(e.to_string()),
                }),
            }
        }
        None => Ok(ExportResult {
            ok: false,
            error: None,
        }),
    }
}

// ══════════════════════════════════════════════════════════════
// SECRET SCANNER  (finds secrets COMMITTED to git, i.e. pushed to GitHub)
// ══════════════════════════════════════════════════════════════

#[derive(Clone, Serialize)]
struct Finding {
    repo: String,     // repo folder name
    path: String,     // absolute file path
    kind: String,     // what kind of secret / issue
    detail: String,   // redacted hint or explanation (never the raw secret)
    line: u32,        // 1-based line, or 0 for a file-level / history finding
    severity: u8,     // 3 = critical, 2 = high, 1 = review
    remote: bool,     // repo has a git remote (so it is on GitHub once pushed)
    commit: String,   // "<short-hash> (<date>)" for history findings, else empty
}

#[derive(Serialize)]
struct SecretScanResult {
    findings: Vec<Finding>,
    repos: u64,
    files: u64,
}

#[derive(Clone, Serialize)]
struct SecretProgress {
    files: u64,
    found: u64,
}

struct SecretRule {
    name: &'static str,
    severity: u8,
    re: Regex,
    generic: bool, // value is in capture group 1; skip obvious placeholders
}

// High-signal patterns first (provider-specific), then one broad "assignment"
// rule that is filtered against placeholder values to keep the noise down.
fn secret_rules() -> &'static [SecretRule] {
    static RULES: OnceLock<Vec<SecretRule>> = OnceLock::new();
    RULES.get_or_init(|| {
        let mk = |name: &'static str, severity: u8, pat: &str, generic: bool| SecretRule {
            name,
            severity,
            re: Regex::new(pat).expect("valid secret regex"),
            generic,
        };
        vec![
            mk("Private key", 3, r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", false),
            mk("Service account key", 3, r#""type"\s*:\s*"service_account""#, false),
            mk("AWS access key", 3, r"(?:AKIA|ASIA)[0-9A-Z]{16}", false),
            mk("Google API key", 3, r"AIza[0-9A-Za-z_\-]{35}", false),
            // (Google OAuth client IDs are public by design, so they are not flagged.)
            mk("GitHub token", 3, r"gh[pousr]_[0-9A-Za-z]{36,}", false),
            mk("GitHub fine-grained token", 3, r"github_pat_[0-9A-Za-z_]{22,}", false),
            mk("Slack token", 2, r"xox[baprs]-[0-9A-Za-z\-]{10,}", false),
            mk("Slack webhook", 2, r"https://hooks\.slack\.com/services/[A-Za-z0-9_/]{20,}", false),
            mk("Stripe secret key", 3, r"(?:sk|rk)_live_[0-9A-Za-z]{16,}", false),
            mk("SendGrid API key", 3, r"SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}", false),
            mk("Twilio key", 2, r"SK[0-9a-fA-F]{32}", false),
            mk("npm token", 2, r"npm_[0-9A-Za-z]{36}", false),
            mk("JSON Web Token", 1, r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}", false),
            mk(
                "Hardcoded secret",
                1,
                r#"(?i)(?:api[_-]?key|secret|token|passwd|password|access[_-]?key|auth[_-]?token|client[_-]?secret|private[_-]?key)["']?\s*[:=]\s*["']([^"'\s]{8,})["']"#,
                true,
            ),
        ]
    })
}

// True when a captured value is obviously not a real secret (placeholder, env
// reference, repeated chars). Keeps the broad rule from crying wolf.
fn is_placeholder(value: &str) -> bool {
    let l = value.to_lowercase();
    const BAD: &[&str] = &[
        "example", "your", "changeme", "change_me", "placeholder", "xxxx", "0000",
        "1234", "test", "sample", "dummy", "todo", "redacted", "insert", "here",
        "<", ">", "${", "process.env", "import.meta", "os.environ", "getenv",
        "env[", "env(", "vault(", "secret(", // env / vault references, not literals
        "null", "none", "true", "false", "undefined",
    ];
    if BAD.iter().any(|b| l.contains(b)) {
        return true;
    }
    // Code, not a literal value: a call, object, template, or string concatenation
    // (e.g. `"?token=" + encodeURIComponent(token)`). Base64 chars (+ / =) are kept.
    if value.contains(['(', ')', '{', '}', '`', '\\', '$']) {
        return true;
    }
    let distinct: HashSet<char> = value.chars().collect();
    distinct.len() <= 3
}

// Show enough to recognize the hit without ever printing the secret.
fn redact(matched: &str) -> String {
    let shown: String = matched.chars().take(4).collect();
    format!("{}... (redacted)", shown)
}

// A committed file that is a secret by its very type: a private key, keystore, or
// certificate. Their presence in git is a leak and they cannot be content-scanned.
// Text config (.env, .npmrc, key.properties) is deliberately NOT flagged by name -
// the content scan catches real secrets inside it, which avoids crying wolf over a
// committed .env that only holds a harmless build flag.
fn is_committed_secret_file(leaf_lower: &str) -> bool {
    if leaf_lower.contains("example") || leaf_lower.contains("sample") || leaf_lower.contains("template") {
        return false;
    }
    const HARD: &[&str] = &[
        ".jks", ".keystore", ".pfx", ".p12", ".pem", ".key", ".p8", ".ppk", ".mobileprovision",
    ];
    if HARD.iter().any(|e| leaf_lower.ends_with(e)) {
        return true;
    }
    matches!(leaf_lower, "id_rsa" | "id_dsa" | "id_ecdsa" | "id_ed25519")
}

// Skip files that are binary, generated, or lock files (lock files are the #1
// source of secret-scanner false positives - they are full of hashes).
fn is_scannable_text(leaf_lower: &str) -> bool {
    const LOCK: &[&str] = &[
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "cargo.lock", "composer.lock",
        "gemfile.lock", "poetry.lock", "go.sum", "packages.lock.json", "flake.lock",
    ];
    if LOCK.contains(&leaf_lower) {
        return false;
    }
    if leaf_lower.ends_with(".min.js") || leaf_lower.ends_with(".min.css") || leaf_lower.ends_with(".map") {
        return false;
    }
    const BIN_EXT: &[&str] = &[
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".pdf", ".psd",
        ".zip", ".gz", ".tgz", ".7z", ".tar", ".rar", ".xz", ".bz2",
        ".exe", ".dll", ".so", ".dylib", ".bin", ".wasm", ".node", ".class", ".jar",
        ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".mov", ".avi",
        ".mkv", ".ogg", ".wav", ".flac", ".o", ".a", ".lib", ".pdb", ".msix", ".appx",
        ".traineddata", ".onnx", ".pt", ".model",
    ];
    !BIN_EXT.iter().any(|e| leaf_lower.ends_with(e))
}

// Directory names never worth descending into while hunting for repo roots.
fn skip_for_repo_hunt(name_lower: &str) -> bool {
    matches!(
        name_lower,
        "node_modules" | "target" | "vendor" | "dist" | "build" | ".gradle" | ".dart_tool"
    )
}

fn find_git_repos(root: &Path, out: &mut Vec<PathBuf>, depth: u32) {
    if depth > 8 || out.len() > 5000 {
        return;
    }
    if root.join(".git").exists() {
        out.push(root.to_path_buf());
        return; // a repo root; do not descend further
    }
    let entries = match fs::read_dir(root) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        let md = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if is_reparse(&md) || !md.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_lowercase();
        if skip_for_repo_hunt(&name) {
            continue;
        }
        find_git_repos(&path, out, depth + 1);
    }
}

fn git_tracked_files(repo: &Path) -> Vec<String> {
    let repo_str = match repo.to_str() {
        Some(s) => s,
        None => return Vec::new(),
    };
    let output = match git_command()
        .args(["-C", repo_str, "ls-files", "-z"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    output
        .stdout
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

fn git_has_remote(repo: &Path) -> bool {
    let repo_str = match repo.to_str() {
        Some(s) => s,
        None => return false,
    };
    git_command()
        .args(["-C", repo_str, "remote"])
        .output()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false)
}

// Test one line of text against every rule. Returns the first real hit as
// (kind, severity, redacted-detail). Shared by the current-commit and full-history
// scans so both apply the exact same detection and false-positive guards.
fn scan_line(line: &str) -> Option<(&'static str, u8, String)> {
    if line.len() > 5000 {
        return None; // minified / data line
    }
    for rule in secret_rules() {
        if let Some(caps) = rule.re.captures(line) {
            if rule.generic {
                let val = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                if is_placeholder(val) {
                    continue;
                }
            }
            // The private-key header often shows up as a string literal in code that
            // parses a key loaded at runtime (e.g. `pem.replace("-----BEGIN PRIVATE
            // KEY-----", "")`). That is not a committed key, so skip when the marker
            // is immediately quoted or the line is clearly doing string surgery.
            if rule.name == "Private key" {
                let end = caps.get(0).map(|m| m.end()).unwrap_or(0);
                let after = line.get(end..).unwrap_or("");
                if after.starts_with('"') || after.starts_with('\'') || line.contains("replace") {
                    continue;
                }
            }
            let matched = caps.get(0).map(|m| m.as_str()).unwrap_or("");
            return Some((rule.name, rule.severity, redact(matched)));
        }
    }
    None
}

// Scan one file's current text for secret patterns, appending findings.
fn scan_file_content(path: &Path, repo: &str, remote: bool, findings: &mut Vec<Finding>) {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(_) => return,
    };
    // A NUL byte in the head means binary; skip.
    if bytes.iter().take(8000).any(|&b| b == 0) {
        return;
    }
    let text = String::from_utf8_lossy(&bytes);
    let mut per_file = 0;
    for (idx, line) in text.lines().enumerate() {
        if let Some((kind, severity, detail)) = scan_line(line) {
            findings.push(Finding {
                repo: repo.to_string(),
                path: path.to_string_lossy().into_owned(),
                kind: kind.to_string(),
                detail,
                line: idx as u32 + 1,
                severity,
                remote,
                commit: String::new(),
            });
            per_file += 1;
            if per_file >= 25 {
                break;
            }
        }
    }
}

// Scan a repo's entire git history (all branches) for secrets that were ever
// committed, even if later removed. Reads `git log -p` and checks added lines.
fn scan_repo_history(
    control: &Arc<AtomicU8>,
    repo: &Path,
    repo_name: &str,
    remote: bool,
    findings: &mut Vec<Finding>,
) {
    let repo_str = match repo.to_str() {
        Some(s) => s,
        None => return,
    };
    // \x01-delimited header so a commit line is unambiguous: \x01<short-hash>\x01<date>
    let output = match git_command()
        .args([
            "-C",
            repo_str,
            "log",
            "--all",
            "--no-color",
            "-p",
            "-U0",
            "--format=%x01%h%x01%as",
        ])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return,
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut commit = String::new();
    let mut file = String::new();
    let mut file_ok = false;
    let mut seen: HashSet<String> = HashSet::new();
    for line in text.lines() {
        if control.load(Ordering::Relaxed) == STOPPED {
            return;
        }
        if let Some(rest) = line.strip_prefix('\u{1}') {
            let mut p = rest.splitn(2, '\u{1}');
            let hash = p.next().unwrap_or("");
            let date = p.next().unwrap_or("");
            commit = format!("{} ({})", hash, date);
            continue;
        }
        if let Some(f) = line.strip_prefix("+++ b/") {
            file = f.to_string();
            let leaf = file.rsplit(['/', '\\']).next().unwrap_or(&file).to_lowercase();
            file_ok = is_scannable_text(&leaf);
            continue;
        }
        // Only added content lines matter (a single leading '+', not the '+++' header).
        if !file_ok || !line.starts_with('+') || line.starts_with("+++") {
            continue;
        }
        let added = &line[1..];
        if let Some((kind, severity, detail)) = scan_line(added) {
            // One row per distinct secret+file, even if it spans many commits.
            let key = format!("{}\u{0}{}\u{0}{}", kind, file, detail);
            if seen.insert(key) {
                findings.push(Finding {
                    repo: repo_name.to_string(),
                    path: repo.join(&file).to_string_lossy().into_owned(),
                    kind: kind.to_string(),
                    detail,
                    line: 0,
                    severity,
                    remote,
                    commit: commit.clone(),
                });
            }
        }
    }
}

fn run_secret_scan(
    app: AppHandle,
    control: Arc<AtomicU8>,
    root: String,
    history: bool,
) -> SecretScanResult {
    let mut repos = Vec::new();
    find_git_repos(Path::new(&root), &mut repos, 0);
    let repo_count = repos.len() as u64;

    let mut findings: Vec<Finding> = Vec::new();
    let mut files_scanned: u64 = 0;
    const MAX_SCAN_SIZE: u64 = 2 * 1024 * 1024;

    for repo in &repos {
        if control.load(Ordering::Relaxed) == STOPPED {
            break;
        }
        let remote = git_has_remote(repo);
        let repo_name = repo
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| repo.to_string_lossy().into_owned());

        // Full-history mode: read every commit's added lines instead of the working tree.
        if history {
            scan_repo_history(&control, repo, &repo_name, remote, &mut findings);
            files_scanned += 1; // repos processed, for the progress ticker
            let _ = app.emit(
                "secret-progress",
                SecretProgress {
                    files: files_scanned,
                    found: findings.len() as u64,
                },
            );
            continue;
        }

        for rel in git_tracked_files(repo) {
            if control.load(Ordering::Relaxed) == STOPPED {
                break;
            }
            let path = repo.join(&rel);
            let leaf = path
                .file_name()
                .map(|n| n.to_string_lossy().to_lowercase())
                .unwrap_or_default();

            if is_committed_secret_file(&leaf) {
                findings.push(Finding {
                    repo: repo_name.clone(),
                    path: path.to_string_lossy().into_owned(),
                    kind: "Committed secret file".to_string(),
                    detail: "This file type holds secrets and should be git-ignored, not committed".to_string(),
                    line: 0,
                    severity: 3,
                    remote,
                    commit: String::new(),
                });
            }

            if is_scannable_text(&leaf) {
                if let Ok(md) = fs::metadata(&path) {
                    if md.len() <= MAX_SCAN_SIZE {
                        scan_file_content(&path, &repo_name, remote, &mut findings);
                        files_scanned += 1;
                        if files_scanned % 200 == 0 {
                            let _ = app.emit(
                                "secret-progress",
                                SecretProgress {
                                    files: files_scanned,
                                    found: findings.len() as u64,
                                },
                            );
                        }
                    }
                }
            }
        }
    }

    // Most severe first, then by repo and path.
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.repo.cmp(&b.repo))
            .then_with(|| a.path.cmp(&b.path))
            .then_with(|| a.line.cmp(&b.line))
    });

    SecretScanResult {
        findings,
        repos: repo_count,
        files: files_scanned,
    }
}

#[tauri::command]
async fn scan_secrets(
    app: AppHandle,
    control: State<'_, ScanControl>,
    root: String,
    history: bool,
) -> Result<SecretScanResult, String> {
    if root.trim().is_empty() || !Path::new(&root).is_dir() {
        return Err("That folder could not be found.".into());
    }
    if !git_is_available() {
        return Err("Git is not installed, so the secret scan cannot read your repositories.".into());
    }
    let ctrl = Arc::new(AtomicU8::new(RUNNING));
    {
        *control.0.lock().unwrap() = Some(ctrl.clone());
    }
    let app2 = app.clone();
    let result = tauri::async_runtime::spawn_blocking(move || run_secret_scan(app2, ctrl, root, history))
        .await
        .map_err(|e| e.to_string())?;
    Ok(result)
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(ScanControl(Mutex::new(None)))
        .invoke_handler(tauri::generate_handler![
            scan,
            scan_secrets,
            stop_scan,
            pause_scan,
            resume_scan,
            path_exists,
            delete_files,
            show_in_explorer,
            open_external,
            pick_folder,
            set_window_theme,
            copy_text,
            export_data
        ])
        .run(tauri::generate_context!())
        .expect("error while running Repo Declutter");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sibs(items: &[&str]) -> HashSet<String> {
        items.iter().map(|s| s.to_lowercase()).collect()
    }

    #[test]
    fn unambiguous_caches_are_flagged() {
        let none = sibs(&[]);
        assert!(match_rule("node_modules", &none, Path::new(".")).is_some());
        assert!(match_rule("__pycache__", &none, Path::new(".")).is_some());
        assert!(match_rule(".gradle", &none, Path::new(".")).is_some());
        assert!(match_rule("dist-newstyle", &none, Path::new(".")).is_some());
        assert!(match_rule("zig-out", &none, Path::new(".")).is_some());
        assert_eq!(
            match_rule("target", &sibs(&["cargo.toml"]), Path::new(".")),
            Some("Rust build")
        );
    }

    // The most important safety guarantee: a generic folder name must NOT be
    // treated as clutter unless a real build-system marker sits beside it.
    #[test]
    fn generic_names_need_a_marker() {
        let plain = sibs(&["readme.md", "src", "index.js"]);
        for name in ["build", "dist", "out", "bin", "obj", "target", "temp", "vendor", "deps"] {
            assert_eq!(
                match_rule(name, &plain, Path::new(".")),
                None,
                "generic name '{name}' must not be flagged without a project marker"
            );
        }
    }

    #[test]
    fn markers_enable_generic_names() {
        assert_eq!(
            match_rule("build", &sibs(&["pubspec.yaml"]), Path::new(".")),
            Some("Build output")
        );
        assert_eq!(
            match_rule("build", &sibs(&["cmakelists.txt"]), Path::new(".")),
            Some("Build output")
        );
        assert_eq!(
            match_rule("bin", &sibs(&["app.csproj"]), Path::new(".")),
            Some(".NET build")
        );
        assert_eq!(
            match_rule("dist", &sibs(&["package.json"]), Path::new(".")),
            Some("JS build output")
        );
        assert_eq!(
            match_rule("temp", &sibs(&["projectsettings", "assets"]), Path::new(".")),
            Some("Unity cache")
        );
        assert_eq!(
            match_rule("intermediate", &sibs(&["mygame.uproject"]), Path::new(".")),
            Some("Unreal build")
        );
    }

    // inside_any rules must actually look inside the candidate folder.
    #[test]
    fn inside_marker_gates_venv_and_go_vendor() {
        let base = std::env::temp_dir().join(format!("rdc_test_{}", std::process::id()));

        let venv = base.join("venv");
        fs::create_dir_all(&venv).unwrap();
        assert_eq!(match_rule("venv", &sibs(&[]), &venv), None); // no pyvenv.cfg inside
        fs::write(venv.join("pyvenv.cfg"), b"home = x").unwrap();
        assert_eq!(match_rule("venv", &sibs(&[]), &venv), Some("Python venv"));

        let vendor = base.join("vendor");
        fs::create_dir_all(&vendor).unwrap();
        assert_eq!(match_rule("vendor", &sibs(&["go.mod"]), &vendor), None); // no modules.txt
        fs::write(vendor.join("modules.txt"), b"# x").unwrap();
        assert_eq!(match_rule("vendor", &sibs(&["go.mod"]), &vendor), Some("Go vendor"));

        let _ = fs::remove_dir_all(&base);
    }

    // Git mode returns EVERYTHING the repo ignores - dirs and loose files alike.
    // Nothing is silently filtered; the user's exclude list is the only gate.
    #[test]
    fn git_parser_returns_everything_ignored() {
        let sample = "\
src-tauri/target/
node_modules/
.claude/
config/secrets/
dist/installer.msix
android/upload-keystore.jks
config/.env
lib/secrets.dart
";
        let repo = Path::new("C:/repo");
        let got: Vec<String> = parse_ignored_paths(sample, repo)
            .iter()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .collect();

        for expected in [
            "C:/repo/src-tauri/target",
            "C:/repo/node_modules",
            "C:/repo/.claude",
            "C:/repo/config/secrets",
            "C:/repo/dist/installer.msix",
            "C:/repo/android/upload-keystore.jks",
            "C:/repo/config/.env",
            "C:/repo/lib/secrets.dart",
        ] {
            assert!(got.contains(&expected.to_string()), "{expected} should be listed");
        }
    }

    // The user's exclude list is the only thing that removes items: it matches a
    // whole name (.claude, node_modules) or a file ending (msix -> anything.msix).
    #[test]
    fn exclude_list_matches_names_and_endings() {
        let ex: Vec<String> = vec![".claude".into(), "node_modules".into(), "msix".into()];
        assert!(is_excluded(&ex, Path::new("C:/r/.claude")));
        assert!(is_excluded(&ex, Path::new("C:/r/a/node_modules")));
        assert!(is_excluded(&ex, Path::new("C:/r/dist/App_1.0.0.msix")));
        // A dot-folder token also hides files INSIDE that folder.
        assert!(is_excluded(&ex, Path::new("C:/r/sidewire/.claude/settings.local.json")));
        // But a plain extension token must NOT wipe the contents of a folder
        // that happens to share its name (files under a real "msix" build folder).
        assert!(!is_excluded(&ex, Path::new("C:/r/format-reaper/msix/build.log")));
        assert!(!is_excluded(&ex, Path::new("C:/r/src-tauri/target")));
        assert!(!is_excluded(&ex, Path::new("C:/r/build.log")));
        assert!(!is_excluded(&[], Path::new("C:/r/anything")));
    }

    // --- Secret scanner ---

    // Uses the real production line scanner.
    fn find_secret(text: &str) -> Option<String> {
        for line in text.lines() {
            if let Some((kind, _, _)) = scan_line(line) {
                return Some(kind.to_string());
            }
        }
        None
    }

    #[test]
    fn scanner_flags_real_secrets() {
        // Fixtures are split across pieces (concat!) so this test file does not
        // itself trip GitHub push protection; concat rebuilds the full value.
        let aws = concat!("AKIA", "IOSFODNN7EXAMPLE");
        assert_eq!(find_secret(&format!("aws_key = {aws}")).as_deref(), Some("AWS access key"));
        let goog = concat!("AIza", "SyA1234567890abcdefghijklmnopqrstuvw");
        assert_eq!(find_secret(&format!("const k = '{goog}'")).as_deref(), Some("Google API key"));
        let ghtok = concat!("ghp_", "0123456789abcdefghijklmnopqrstuvwxyz");
        assert_eq!(find_secret(&format!("token: {ghtok}")).as_deref(), Some("GitHub token"));
        let stripe = concat!("sk_", "live_0123456789abcdefghijABCD");
        assert_eq!(find_secret(&format!("STRIPE={stripe}")).as_deref(), Some("Stripe secret key"));
        assert!(find_secret("-----BEGIN RSA PRIVATE KEY-----").is_some());
        assert!(find_secret(r#"{ "type": "service_account", "project_id": "x" }"#).is_some());
        assert_eq!(find_secret(r#"apiKey = "sup3rSecretValue123""#).as_deref(), Some("Hardcoded secret"));
    }

    #[test]
    fn scanner_ignores_placeholders_and_clean_code() {
        assert_eq!(find_secret("let x = 5; // normal code"), None);
        assert_eq!(find_secret(r#"apiKey = "your-api-key-here""#), None);
        assert_eq!(find_secret(r#"password = "${DB_PASSWORD}""#), None);
        assert_eq!(find_secret(r#"token = process.env.TOKEN"#), None);
        assert_eq!(find_secret(r#"secret = "changeme""#), None);
        // Real-world false positives that used to fire:
        // Supabase env() references.
        assert_eq!(find_secret(r#"openai_api_key = "env(OPENAI_API_KEY)""#), None);
        assert_eq!(find_secret(r#"secret = "env(SUPABASE_AUTH_EXTERNAL_APPLE_SECRET)""#), None);
        // Code that parses a key loaded at runtime (not a committed key).
        assert_eq!(find_secret(r#"const b = pem.replace("-----BEGIN PRIVATE KEY-----", "")"#), None);
        // JS string concatenation building a URL with a runtime variable.
        assert_eq!(find_secret(r#"fetch("/api/messages?token=" + encodeURIComponent(token))"#), None);
    }

    #[test]
    fn scanner_skips_lockfiles_and_binaries() {
        assert!(!is_scannable_text("package-lock.json"));
        assert!(!is_scannable_text("cargo.lock"));
        assert!(!is_scannable_text("logo.png"));
        assert!(!is_scannable_text("bundle.min.js"));
        assert!(is_scannable_text("config.dart"));
        assert!(is_scannable_text(".env"));
        // Only real key / cert files are flagged by name. Text config (.env, .npmrc)
        // relies on content scanning, so a benign committed .env is not cried over.
        assert!(is_committed_secret_file("upload-keystore.jks"));
        assert!(is_committed_secret_file("server.pem"));
        assert!(is_committed_secret_file("id_rsa"));
        assert!(!is_committed_secret_file(".env"));
        assert!(!is_committed_secret_file(".npmrc"));
        assert!(!is_committed_secret_file("cert.pem.example"));
    }
}

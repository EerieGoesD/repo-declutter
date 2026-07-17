# Repo Declutter

Repo Declutter is a Windows tool for developers whose code folder has grown into gigabytes of build junk. It does three things, all on your own machine: it clears regenerable build and cache folders to reclaim disk space, scans your repositories for secrets committed by mistake, and flags build clutter that was committed to git when it should have been ignored.

## Declutter

- Point it at any folder (like your whole GitHub folder) and it scans every repository inside.
- Finds only regenerable clutter such as `node_modules`, Rust `target`, `.NET` `bin`/`obj`, Flutter and Gradle `build`, and Python caches. It never touches your source.
- Shows each item's type, size and last-modified date, with a minimum-size filter so you focus on the space hogs.
- Send what you pick to the Recycle Bin, reveal it in Explorer first, or export the list as CSV or TXT.
- Exclude anything you want to keep, by name, folder or file ending.

## Secret Scan

- Finds API keys, tokens and private keys committed to git, so you catch them before they reach the world.
- An optional full-history scan catches secrets that were committed long ago and later removed but still live in the history.
- Read-only. It never shows the secret itself, only enough for you to find it.

## Repo Health

- Finds build folders and OS files that were committed to a repository when they should have been ignored.
- An optional full-history scan catches clutter buried in old commits.
- Shows the exact command to put each one right, and never deletes anything itself.

## Get the app

- Microsoft Store: https://apps.microsoft.com/detail/9NBF8X77NS3N
- Or build it yourself: it is a Tauri 2 app, built from the project root with `cargo tauri build`.

---

Made by [EERIE](https://eeriegoesd.com) | [Support This Project](https://buymeacoffee.com/eeriegoesd) | [Report Issue](https://github.com/EerieGoesD/repo-declutter/issues/new?template=bug-report.md) | [Feedback](https://github.com/EerieGoesD/repo-declutter/discussions) | [Feature Request](https://github.com/EerieGoesD/repo-declutter/issues/new?template=feature-request.md)

# Repo Declutter

A fast, lightweight Windows tool that scans your code folder and finds the build outputs and caches that quietly eat your disk - `node_modules`, Rust `target`, `.NET` `bin`/`obj`, Flutter/Gradle `build`, Python caches, and more. Everything it lists is safe to remove because your tools regenerate it on the next build. Pick what you don't need and send it to the Recycle Bin. Built with Tauri.

## What it does

- Point it at any folder (like your whole GitHub folder) and scan every repo inside it.
- Finds only regenerable clutter - dependency, build, and cache folders - never your source code.
- Shows each item's type, size, and last-modified date so you know exactly what you're clearing.
- Hide the small stuff with a minimum-size filter so you focus on the space hogs.
- Select what you want and move it to the Recycle Bin, or reveal it in Explorer first.
- Right-click any result to copy its path or open it in Explorer.
- Export the list as CSV or TXT.

---

Made by [EERIE](https://eeriegoesd.com) | [Support This Project](https://buymeacoffee.com/eeriegoesd) | [Report Issue](https://github.com/EerieGoesD/repo-declutter/issues/new?template=bug-report.md) | [Feedback](https://github.com/EerieGoesD/repo-declutter/discussions) | [Feature Request](https://github.com/EerieGoesD/repo-declutter/issues/new?template=feature-request.md)

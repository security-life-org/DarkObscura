# DarkObscura UI (Tauri v2 + WebGL)

Desktop shell implementing the **Progressive Disclosure** paradigm with three modes:

- **Zen / Autopilot** — enter a URL; the AI/engine works in the background and the WebGL
  *Attack Graph* surfaces exploitable nodes in red for one-click action.
- **Tactical / Intercept** — a Burp/Caido-style request/response workbench with smart
  highlighting of risky parameters and a `Ctrl+K` command palette.
- **God / Kernel** — raw AST editor, eBPF trace viewer, WASM scripting console, hex editor.

## Stack
- Tauri v2 (Rust shell) — talks to `cmd/core` over local WebSocket/IPC.
- Vanilla + Three.js for the attack-graph WebGL scene (swap for Svelte/React as it grows).

## Develop
```bash
npm install
npm run tauri dev     # requires the Rust toolchain + Tauri v2 CLI
```

The Go backend must be running (`go run ./cmd/core --i-have-authorization`).

`index.html` is a runnable browser prototype of the shell + attack graph (open directly or via
`npm run dev`) so the UI can be iterated without the full Tauri build.

# profiler-viewer

WASM library that processes profiler JSONL output into structured JSON for the HTML viewer.

## Build

Requires [`wasm-pack`](https://rustwasm.github.io/wasm-pack/installer/):

```bash
cargo install wasm-pack
```

Build the WASM package:

```bash
wasm-pack build --target web --out-dir pkg
```

Output goes to `pkg/` - import it from `index.html`:

```js
import init, { process_jsonl } from './pkg/profiler_viewer.js';
await init();
const data = JSON.parse(process_jsonl(jsonlText));
```

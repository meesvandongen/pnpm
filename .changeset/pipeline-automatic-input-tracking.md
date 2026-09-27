---
"pacquet": minor
---

`pnpm pipeline` can now find a task's cache inputs and outputs by watching the files the task uses. Add `{ auto: true }` to a task's `inputs` in `pnpm-workspace.yaml` and the files its scripts read, probe, or list inside the workspace become its inputs. Add it to `outputs` and the files the task writes inside its project are cached and restored. A `!` prefix on a glob in `inputs` or `outputs` excludes the files it matches.

```yaml
tasks:
  build:
    inputs: [{ auto: true }, '!*.log']
    outputs: [{ auto: true }]
```

pnpm does not cache a run that changed a file it read, or whose inputs changed while it ran.

Automatic tracking works on Linux 5.8 or later, macOS, and Windows. On macOS, tracked scripts run with a POSIX shell and core utilities that pnpm ships, because macOS does not let pnpm observe its own. A task whose file accesses cannot all be observed, such as one that runs another macOS system program, runs without the cache, and pnpm prints a warning.

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

Automatic tracking works on Linux. On other platforms, and with `shellEmulator` enabled, such a task runs without the cache and pnpm prints a warning.

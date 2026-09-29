---
"pacquet": patch
---

`pnpm pipeline` keeps caching a task whose outputs differ between runs with the same inputs, such as a build that writes a timestamp. Before, storing such a task could fail with a warning, and every later run of it missed the cache until the cache directory was cleared.

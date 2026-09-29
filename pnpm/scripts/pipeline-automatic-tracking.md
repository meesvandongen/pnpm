# Automatic input tracking in a pipeline

By default, a `pnpm pipeline` task's cache key covers every file Git tracks in
its project (plus untracked files that are not ignored), narrowed by the task's
`inputs` globs. With automatic tracking, pnpm instead watches the task's
scripts run and records the files they use:

```yaml
pipelines:
  default: [build]
tasks:
  build:
    dependsOn: ['^build']
    inputs: [{ auto: true }]
    outputs: [{ auto: true }]
```

## What is recorded

Every process a script starts is traced, including the processes those start.
pnpm records:

- files the task read, and programs it executed,
- paths it checked for existence or metadata, including paths that did not
  exist,
- directories whose entries it listed,
- files it wrote.

The paths the task read, checked, or listed inside the workspace become its
inputs. A read file is fingerprinted by its contents, a listed directory by its
entry names, and a checked path only by whether it exists and what kind of
entry it is. On Windows, a program can also ask a directory for the entries
whose names match a pattern, the way `cmd` looks for `node.*` when a script
runs `node`. Such a query is fingerprinted by the names that match.

On the next run pnpm fingerprints the same paths again. If every fingerprint
matches, the stored result is restored. Otherwise the task runs and its record
is added. pnpm keeps the paths of a task's last 8 recorded runs, because a
changed script can read other files. Putting the workspace back in an earlier
state, such as reverting that script, restores the result stored for it.

Because inputs are observed, a task picks up files that the default input set
misses, such as a Git-ignored `.env.local` that a build reads, or a file in a
sibling workspace package reached through `node_modules`. It also ignores
files in its project that it never touches, such as a README.

These paths are never inputs:

- paths outside the workspace root,
- paths inside a `node_modules` directory, which the lockfile already covers
  (a workspace package reached through a `node_modules` link is recorded at
  its real location),
- paths the task wrote,
- paths inside the project that match the task's `outputs` globs.

pnpm does not cache a run in two cases, and prints a warning naming the file:

- The task read a file and then changed it, the way `eslint --fix` or a
  formatter does. The stored result would not match the file the next run
  sees. Add the file to the task's `outputs`, or exclude it with `!` in its
  `inputs`, to cache the task anyway.
- An input changed while the task ran, for example because you saved a file
  mid-build. The next run rebuilds with the new contents. This includes a
  directory the task listed that another task, running at the same time,
  created files in: a linter that lists its project while a build writes
  `dist` there is cached from the next run on. Make such a task depend on the
  other, with `dependsOn`, to cache it on the first run.

As with any cached task, a tracked task is cached only when it declares
`outputs`. A task that writes nothing worth keeping, such as a linter, declares
`outputs: []`.

With `{ auto: true }` in `outputs`, the files the task wrote inside its project
directory, outside `node_modules` and `.git`, are stored as its outputs and
restored on a cache hit. This also works for a task that keeps Git-based
inputs. Keep the files such a task generates out of its inputs: ignore them in
Git, or match them with an `outputs` glob.

## Refining what is tracked

Entries in `inputs` and `outputs` combine:

```yaml
tasks:
  build:
    # Tracked inputs, plus every Git-tracked file under config/, minus logs.
    inputs: [{ auto: true }, 'config/**', '!**/*.log']
    # Declared outputs and tracked outputs together, minus source maps.
    outputs: [{ auto: true }, 'dist/**', '!**/*.map']
```

- A glob without a prefix adds the Git-tracked files it matches. Without
  `{ auto: true }`, globs keep their existing meaning: they replace the default
  input set, and a `+` prefix adds to it instead.
- A `!` prefix excludes the files it matches. Globs are relative to the project
  directory, so they cannot exclude a path outside it.

Declare in `env` the environment variables that affect the task's result.
Environment reads are not observed.

## Requirements and limits

Tracking works on Linux, macOS, and Windows. On each, a task whose file
accesses cannot all be observed still runs, but its result is not cached,
and pnpm prints a warning. With `shellEmulator` enabled, tracked tasks run
without the cache, and so do the tasks that depend on them.

### Linux

Tracking uses seccomp user notifications and needs Linux 5.8 or later on x86-64
or 64-bit Arm. Each file system call a traced process makes waits for pnpm to
record it. On Linux 6.6 and later the kernel hands the call to pnpm on the same
CPU, which costs a few microseconds per call; older kernels take longer. Other
system calls run at full speed.

A sandbox that forbids seccomp filters, or reading a traced process's memory,
leaves the trace incomplete, and so does a 32-bit program in the process tree.
A traced process cannot gain privileges through a set-user-ID program such as
`sudo`, and cannot set up `io_uring`, so programs fall back to ordinary system
calls.

### macOS

pnpm loads a library into every process of the task through
`DYLD_INSERT_LIBRARIES`. The library records the task's file accesses from
inside each process, so they cost about as much as the calls themselves.

macOS does not load the library into its own programs under `/bin`, `/usr/bin`,
and similar directories. pnpm therefore runs the task's scripts with its own
POSIX shell ([Oils](https://oils.pub)) instead of `/bin/sh`, and runs the core
utilities (`cp`, `rm`, `mkdir`, `cat`, `env`, and the rest of
[uutils](https://github.com/uutils/coreutils)) in place of the system's. A task
that runs another system program, such as `/usr/bin/git`, or a program that
refuses the library, runs without the cache.

### Windows

pnpm loads a library into every process of the task with
[Detours](https://github.com/microsoft/Detours). The library records the
task's file accesses from inside each process. A task that starts a 32-bit
program, or starts a process the library cannot follow, runs without the cache.

### On every platform

Processes a script leaves running in the background keep running, but their
file accesses after the script exits are not recorded. On Linux, their file
system calls fail once pnpm exits.

A task with `cargoTargetDir` keeps its Git-based inputs, which its Cargo
snapshots are keyed on. `{ auto: true }` in its `inputs` has no effect.

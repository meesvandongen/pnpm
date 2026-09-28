use super::{contains, fixture, node, observed};
use std::fs;

#[test]
fn read_file_sync_is_a_read() {
    let (_temp, dir) = fixture();
    fs::write(dir.join("input.txt"), "x").unwrap();
    let accesses = node(&dir, "fs.readFileSync('input.txt')");
    assert!(contains(&accesses.reads, &dir.join("input.txt")));
}

#[test]
fn a_missing_file_read_is_a_read() {
    let (_temp, dir) = fixture();
    let accesses = node(&dir, "try { fs.readFileSync('missing.txt') } catch {}");
    assert!(observed(&accesses, &dir.join("missing.txt")));
}

#[test]
fn exists_sync_makes_the_path_an_input() {
    let (_temp, dir) = fixture();
    let accesses = node(&dir, "fs.existsSync('missing.txt')");
    assert!(observed(&accesses, &dir.join("missing.txt")));
}

#[test]
fn stat_sync_makes_the_path_an_input() {
    let (_temp, dir) = fixture();
    fs::write(dir.join("input.txt"), "x").unwrap();
    let accesses = node(&dir, "fs.statSync('input.txt'); fs.lstatSync('input.txt')");
    assert!(observed(&accesses, &dir.join("input.txt")));
}

#[test]
fn a_read_stream_is_a_read() {
    let (_temp, dir) = fixture();
    fs::write(dir.join("input.txt"), "x").unwrap();
    let accesses = node(&dir, "fs.createReadStream('input.txt').on('data', () => {})");
    assert!(contains(&accesses.reads, &dir.join("input.txt")));
}

#[test]
fn promises_read_on_the_thread_pool_are_reads() {
    let (_temp, dir) = fixture();
    for index in 0..8 {
        fs::write(dir.join(format!("{index}.txt")), "x").unwrap();
    }
    let accesses = node(
        &dir,
        "Promise.all(Array.from({ length: 8 }, (_, i) => fs.promises.readFile(`${i}.txt`)))",
    );
    for index in 0..8 {
        assert!(contains(&accesses.reads, &dir.join(format!("{index}.txt"))), "{index}.txt");
    }
}

#[test]
fn write_file_sync_and_write_streams_are_writes() {
    let (_temp, dir) = fixture();
    let accesses = node(
        &dir,
        "fs.writeFileSync('written.txt', 'x'); fs.createWriteStream('streamed.txt').end('x')",
    );
    assert!(contains(&accesses.writes, &dir.join("written.txt")));
    assert!(contains(&accesses.writes, &dir.join("streamed.txt")));
    assert!(accesses.modified_reads.is_empty());
}

#[test]
fn readdir_sync_is_a_listing() {
    let (_temp, dir) = fixture();
    fs::create_dir(dir.join("src")).unwrap();
    fs::write(dir.join("src").join("a.txt"), "a").unwrap();
    let accesses =
        node(&dir, "fs.readdirSync('src'); fs.readdirSync('src', { withFileTypes: true })");
    assert!(contains(&accesses.listings, &dir.join("src")));
}

#[test]
fn opendir_is_a_listing() {
    let (_temp, dir) = fixture();
    fs::create_dir(dir.join("src")).unwrap();
    fs::write(dir.join("src").join("a.txt"), "a").unwrap();
    let accesses = node(&dir, "const d = fs.opendirSync('src'); d.readSync(); d.closeSync()");
    assert!(contains(&accesses.listings, &dir.join("src")));
}

#[test]
fn a_file_a_child_process_reads_is_a_read() {
    let (_temp, dir) = fixture();
    fs::write(dir.join("input.txt"), "x").unwrap();
    let command = if cfg!(windows) {
        "child_process.spawnSync('cmd', ['/d', '/c', 'type input.txt'], { stdio: 'ignore' })"
    } else {
        "child_process.spawnSync('/bin/sh', ['-c', 'cat input.txt'], { stdio: 'ignore' })"
    };
    let accesses = node(&dir, command);
    assert!(contains(&accesses.reads, &dir.join("input.txt")));
}

#[test]
fn a_file_read_by_a_grandchild_through_exec_sync_is_a_read() {
    let (_temp, dir) = fixture();
    fs::write(dir.join("input.txt"), "x").unwrap();
    let accesses =
        node(&dir, "child_process.execSync(`node -e \"require('fs').readFileSync('input.txt')\"`)");
    assert!(contains(&accesses.reads, &dir.join("input.txt")));
}

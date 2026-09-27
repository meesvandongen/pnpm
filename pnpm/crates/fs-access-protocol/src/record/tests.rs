use super::{Access, Event, Record, Truncated, decode_all, encode};
use crate::{PathState, max_record_len};

fn encoded(records: &[Record<'_>]) -> Vec<u8> {
    let mut log = Vec::new();
    for record in records {
        let mut buffer = vec![0u8; max_record_len(64)];
        let len = encode(record, &mut buffer).expect("the buffer is large enough");
        log.extend_from_slice(&buffer[..len]);
    }
    log
}

#[test]
fn records_survive_encoding() {
    let state = PathState::of(std::path::Path::new("/definitely/missing/path"));
    let records = [
        Record { pid: 7, time: 1, event: Event::Began { image: b"/bin/node" } },
        Record {
            pid: 7,
            time: 2,
            event: Event::Accessed { access: Access::Read, state: Some(state), path: b"/w/a.txt" },
        },
        Record {
            pid: 7,
            time: 3,
            event: Event::Accessed { access: Access::Write, state: None, path: b"/w/out" },
        },
        Record { pid: 7, time: 4, event: Event::Spawned { child: 8, image: b"/bin/sh" } },
        Record { pid: 8, time: 5, event: Event::Executing { image: b"/bin/ls" } },
        Record { pid: 8, time: 6, event: Event::ExecFailed },
        Record { pid: 8, time: 7, event: Event::Unrecorded },
    ];
    assert_eq!(decode_all(&encoded(&records)), Ok(records.to_vec()));
}

#[test]
fn a_log_cut_inside_a_record_is_truncated() {
    let log = encoded(&[
        Record { pid: 1, time: 1, event: Event::Began { image: b"/bin/node" } },
        Record { pid: 1, time: 2, event: Event::Executing { image: b"/bin/sh" } },
    ]);
    assert_eq!(decode_all(&log[..log.len() - 3]), Err(Truncated));
}

#[test]
fn a_buffer_too_small_for_the_record_is_refused() {
    let record = Record { pid: 1, time: 1, event: Event::Began { image: &[b'x'; 100] } };
    assert_eq!(encode(&record, &mut [0u8; 64]), None);
}

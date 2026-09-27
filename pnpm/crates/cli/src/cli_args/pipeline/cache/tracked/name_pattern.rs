//! The file name patterns of Windows directory queries, matched the way
//! the file system matches them: without regard to case, with `*` for any
//! run of characters and `?` for any one, and with the DOS wildcards that
//! `FindFirstFileExW` makes of `*`, `?`, and `.` so that `*.*` and `name.*`
//! keep their MS-DOS meaning.
//!
//! - `<` matches any run of characters that stops short of the name's last
//!   `.`.
//! - `>` matches any one character, or nothing at a `.` or at the end of
//!   the name.
//! - `"` matches a `.`, or nothing at the end of the name.

/// Whether the file name `name` matches `pattern`.
pub fn matches(pattern: &str, name: &str) -> bool {
    let pattern: Vec<char> = pattern
        .chars()
        .flat_map(char::to_uppercase)
        .collect();
    let name: Vec<char> = name
        .chars()
        .flat_map(char::to_uppercase)
        .collect();
    let last_dot = name
        .iter()
        .rposition(|character| *character == '.');
    Matcher { name: &name, last_dot }.matches_from(&pattern, 0)
}

struct Matcher<'a> {
    name: &'a [char],
    last_dot: Option<usize>,
}

impl Matcher<'_> {
    /// Whether `pattern` matches the name from character `start` on.
    fn matches_from(&self, pattern: &[char], start: usize) -> bool {
        let next = self.name.get(start).copied();
        let Some((&wildcard, rest)) = pattern.split_first() else {
            return next.is_none();
        };
        match wildcard {
            '*' => (start..=self.name.len()).any(|end| self.matches_from(rest, end)),
            '<' => {
                let stop = self.last_dot
                    .filter(|dot| *dot >= start)
                    .unwrap_or(self.name.len());
                (start..=stop).any(|end| self.matches_from(rest, end))
            }
            '>' if matches!(next, None | Some('.')) => {
                let after = rest
                    .iter()
                    .position(|character| *character != '>')
                    .map_or(&[][..], |index| &rest[index..]);
                self.matches_from(after, start)
            }
            '"' if next.is_none() => self.matches_from(rest, start),
            '"' => next == Some('.') && self.matches_from(rest, start + 1),
            '?' | '>' => next.is_some() && self.matches_from(rest, start + 1),
            literal => next == Some(literal) && self.matches_from(rest, start + 1),
        }
    }
}

#[cfg(test)]
mod tests;

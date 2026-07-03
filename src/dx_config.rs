use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;

pub struct DcpDxConfig {
    pub workspace_root: PathBuf,
    pub sr_dir: PathBuf,
    pub receipts_dir: PathBuf,
}

impl DcpDxConfig {
    pub fn load() -> Self {
        let ws = find_root().unwrap_or_else(|| PathBuf::from("."));
        let sr = ws.join(".dx").join("serializer");
        let receipts = ws.join(".dx").join("receipts").join("dcp");
        Self { workspace_root: ws, sr_dir: sr, receipts_dir: receipts }
    }

    pub fn sr_path(&self, name: &str) -> PathBuf {
        self.sr_dir.join(format!("{}.sr", name))
    }

    pub fn write_sr(&self, name: &str, entries: &[(&str, &str)]) -> std::io::Result<()> {
        let path = self.sr_path(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut buf: Vec<u8> = Vec::new();
        for (key, value) in entries {
            write!(buf, "{key}=")?;
            Self::write_llm_value(&mut buf, value)?;
            buf.push(b'\n');
        }
        let tmp = path.with_extension("sr.tmp");
        std::fs::write(&tmp, &buf)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn read_status(&self, name: &str) -> Option<HashMap<String, String>> {
        let sr_path = self.sr_path(name);
        let (doc, _from_machine) = serializer::try_read_machine_or_sr(&sr_path)?;
        let mut map = HashMap::new();
        for (key, value) in &doc.context {
            map.insert(key.clone(), value.to_string());
        }
        Some(map)
    }

    pub fn machine_path(&self, name: &str) -> PathBuf {
        self.sr_dir.join(format!("{}.machine", name))
    }

    fn write_llm_value(buf: &mut Vec<u8>, value: &str) -> std::io::Result<()> {
        if value.is_empty() {
            buf.extend_from_slice(b"\"\"");
            return Ok(());
        }
        let needs_quoting = value.contains(|c: char| {
            c.is_ascii_whitespace() || c == '"' || c == '[' || c == ']' || c == '=' || c == '#'
        });
        if needs_quoting {
            buf.push(b'"');
            for c in value.chars() {
                if c == '"' || c == '\\' { buf.push(b'\\'); }
                let mut tmp = [0u8; 4];
                buf.extend_from_slice(c.encode_utf8(&mut tmp).as_bytes());
            }
            buf.push(b'"');
        } else {
            buf.extend_from_slice(value.as_bytes());
        }
        Ok(())
    }
}

fn find_root() -> Option<PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    for ancestor in cwd.ancestors() {
        let candidate = ancestor.join("dx");
        if candidate.is_file() {
            let source = std::fs::read_to_string(&candidate).ok()?;
            let first = source.lines().find(|l| {
                let t = l.trim().trim_start_matches('\u{feff}');
                !t.is_empty() && !t.starts_with('#')
            })?;
            if !first.starts_with("project(") && !first.starts_with("contract(") &&
               !first.starts_with("runtime(") && !first.starts_with("www(") &&
               !(first.contains('[') && first.contains('(')) {
                return Some(ancestor.to_path_buf());
            }
        }
    }
    None
}

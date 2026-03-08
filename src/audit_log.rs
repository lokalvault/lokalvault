use crate::vault_file::get_app_data_dir;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessEvent {
    pub timestamp: String,
    // Informational only for the current phase: these fields are client-supplied
    // metadata and are not kernel-verified process identity.
    pub process_name: String,
    pub exe_path: String,
    pub project: String,
    pub key: String,
    pub method: String,
}

#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    pub project: Option<String>,
    pub since: Option<SystemTime>,
    pub method: Option<String>,
    pub process_name: Option<String>,
}

pub fn get_audit_log_path() -> PathBuf {
    get_app_data_dir().join("audit.log")
}

pub fn log_access_event(event: AccessEvent) -> Result<(), String> {
    let path = get_audit_log_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    let line = serde_json::to_string(&event).map_err(|e| e.to_string())?;
    writeln!(file, "{line}").map_err(|e| e.to_string())
}

pub fn read_audit_log(filter: Option<AuditFilter>) -> Result<Vec<AccessEvent>, String> {
    let path = get_audit_log_path();
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    let reader = BufReader::new(file);
    let mut events = Vec::new();

    for line in reader.lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let event: AccessEvent = serde_json::from_str(&line).map_err(|e| e.to_string())?;
        if matches_filter(&event, filter.as_ref())? {
            events.push(event);
        }
    }

    events.reverse();
    Ok(events)
}

pub fn clear_audit_log() -> Result<(), String> {
    let path = get_audit_log_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn matches_filter(event: &AccessEvent, filter: Option<&AuditFilter>) -> Result<bool, String> {
    let Some(filter) = filter else {
        return Ok(true);
    };

    if let Some(project) = &filter.project
        && &event.project != project
    {
        return Ok(false);
    }
    if let Some(method) = &filter.method
        && &event.method != method
    {
        return Ok(false);
    }
    if let Some(process_name) = &filter.process_name
        && &event.process_name != process_name
    {
        return Ok(false);
    }
    if let Some(since) = filter.since {
        let timestamp = DateTime::parse_from_rfc3339(&event.timestamp)
            .map_err(|e| e.to_string())?
            .with_timezone(&Utc);
        let since = DateTime::<Utc>::from(since);
        if timestamp < since {
            return Ok(false);
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::{Duration, UNIX_EPOCH};

    static AUDIT_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn cleanup() {
        let _ = fs::remove_file(get_audit_log_path());
    }

    fn sample_event(project: &str, key: &str, seconds: u64) -> AccessEvent {
        AccessEvent {
            timestamp: DateTime::<Utc>::from(UNIX_EPOCH + Duration::from_secs(seconds))
                .to_rfc3339(),
            process_name: "python".to_string(),
            exe_path: "/usr/bin/python3".to_string(),
            project: project.to_string(),
            key: key.to_string(),
            method: "run_env".to_string(),
        }
    }

    #[test]
    fn test_log_and_read_event() {
        let _guard = AUDIT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        cleanup();

        let event = sample_event("my-app", "OPENAI_KEY", 10);
        log_access_event(event.clone()).unwrap();
        let events = read_audit_log(None).unwrap();

        assert_eq!(events, vec![event]);
        cleanup();
    }

    #[test]
    fn test_filter_by_project() {
        let _guard = AUDIT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        cleanup();

        log_access_event(sample_event("my-app", "OPENAI_KEY", 10)).unwrap();
        log_access_event(sample_event("other-app", "STRIPE_KEY", 20)).unwrap();

        let events = read_audit_log(Some(AuditFilter {
            project: Some("my-app".to_string()),
            ..AuditFilter::default()
        }))
        .unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].project, "my-app");
        cleanup();
    }

    #[test]
    fn test_filter_by_since() {
        let _guard = AUDIT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        cleanup();

        log_access_event(sample_event("my-app", "OLD_KEY", 10)).unwrap();
        log_access_event(sample_event("my-app", "NEW_KEY", 20)).unwrap();

        let events = read_audit_log(Some(AuditFilter {
            since: Some(UNIX_EPOCH + Duration::from_secs(15)),
            ..AuditFilter::default()
        }))
        .unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].key, "NEW_KEY");
        cleanup();
    }

    #[test]
    fn test_clear_audit_log() {
        let _guard = AUDIT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        cleanup();

        log_access_event(sample_event("my-app", "OPENAI_KEY", 10)).unwrap();
        clear_audit_log().unwrap();
        let events = read_audit_log(None).unwrap();

        assert!(events.is_empty());
        cleanup();
    }

    #[test]
    fn test_never_logs_value() {
        let _guard = AUDIT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let event = sample_event("my-app", "OPENAI_KEY", 10);
        let value = serde_json::to_value(&event).unwrap();
        assert!(value.get("value").is_none());
    }
}

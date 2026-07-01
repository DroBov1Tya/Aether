use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use uuid::Uuid;

const TTL: u64 = 1800;

#[derive(Clone, Default)]
pub struct TaskState {
    pub dns: bool,
    pub rustscan: bool,
    pub nmap: bool,
    pub ssl: bool,
    pub whatweb: bool,
    pub whois: bool,
    pub hxn: bool,
}

impl TaskState {
    pub fn keys(&self) -> Vec<&'static str> {
        vec!["dns", "rustscan", "nmap", "ssl", "whatweb", "whois", "hxn"]
    }

    pub fn mandatory_keys(&self) -> Vec<&'static str> {
        vec!["dns", "rustscan", "nmap", "whois"]
    }

    pub fn all_done(&self) -> bool {
        self.dns && self.rustscan && self.nmap && self.ssl && self.whatweb && self.whois && self.hxn
    }
}

fn state_key(task_id: Uuid, field: &str) -> String {
    format!("task:{}:state:{}", task_id, field)
}

fn task_targets_key(task_id: Uuid) -> String {
    format!("task:{}:targets", task_id)
}

fn task_agent_key(task_id: Uuid) -> String {
    format!("task:{}:agent_id", task_id)
}

fn agent_tasks_key(agent_id: Uuid) -> String {
    format!("agent:{}:tasks", agent_id)
}

fn agent_target_count_key(agent_id: Uuid) -> String {
    format!("agent:{}:target_count", agent_id)
}

fn task_target_count_key(task_id: Uuid) -> String {
    format!("task:{}:target_count", task_id)
}

pub async fn init(conn: &mut ConnectionManager, task_id: Uuid) {
    let state = TaskState::default();
    for key in state.mandatory_keys() {
        if let Err(e) = conn
            .set_ex::<_, _, ()>(state_key(task_id, key), false, TTL)
            .await
        {
            tracing::warn!("redis init {} {}: {}", task_id, key, e);
        }
    }
}

pub async fn add_target(conn: &mut ConnectionManager, task_id: Uuid, ip: &str) {
    if let Err(e) = conn.rpush::<_, _, ()>(task_targets_key(task_id), ip).await {
        tracing::error!("redis rpush {} {}: {}", task_id, ip, e);
    }
    if let Err(e) = conn
        .expire::<_, ()>(task_targets_key(task_id), TTL as i64)
        .await
    {
        tracing::warn!("redis expire {}: {}", task_id, e);
    }
}

pub async fn add_targets(conn: &mut ConnectionManager, task_id: Uuid, ips: &[String]) {
    if let Err(e) = conn
        .rpush::<_, _, usize>(task_targets_key(task_id), ips)
        .await
    {
        tracing::error!("redis rpush batch {}: {} (count {})", task_id, e, ips.len());
    }
    if let Err(e) = conn
        .expire::<_, ()>(task_targets_key(task_id), TTL as i64)
        .await
    {
        tracing::warn!("redis expire {}: {}", task_id, e);
    }
}

pub async fn mark_pending(conn: &mut ConnectionManager, task_id: &str) {
    let _: () = conn
        .sadd("distribute:pending", task_id)
        .await
        .unwrap_or_default();
}

pub async fn pop_pending(conn: &mut ConnectionManager) -> Option<String> {
    conn.spop("distribute:pending").await.unwrap_or(None)
}

pub async fn get_targets(
    conn: &mut ConnectionManager,
    task_id: &str,
    start: isize,
    count: isize,
) -> Vec<String> {
    let key = format!("task:{task_id}:targets");
    conn.lrange(key.as_str(), start, start + count - 1)
        .await
        .unwrap_or_default()
}

pub async fn get_target_count(conn: &mut ConnectionManager, task_id: &str) -> u32 {
    let key = format!("task:{task_id}:targets");
    conn.llen(&key).await.unwrap_or(0)
}

pub async fn push_targets(
    _conn: &mut ConnectionManager,
    task_id: Uuid,
    ips: &[String],
    agent_ip: &str,
    agent_port: i32,
    api_key: &str,
) {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_default();

    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(10));
    let api_key = std::sync::Arc::new(api_key.to_string());
    let agent_url = std::sync::Arc::new(format!("http://{}:{}/api/scan", agent_ip, agent_port));
    let mut handles = Vec::new();

    for ip in ips {
        let permit = sem.clone().acquire_owned().await.expect("semaphore");
        let client = client.clone();
        let api_key = std::sync::Arc::clone(&api_key);
        let msg = serde_json::json!({"target": ip, "task_uid": task_id.to_string()});
        let url = agent_url.to_string();
        let ip = ip.clone();

        handles.push(tokio::spawn(async move {
            let result = client
                .post(&url)
                .header("X-API-KEY", api_key.as_str())
                .json(&msg)
                .send()
                .await;
            match result {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!("pushed {} to task {}", ip, task_id);
                }
                Ok(resp) => {
                    tracing::warn!("agent {} rejected {}: {}", url, ip, resp.status());
                }
                Err(e) => {
                    tracing::error!("failed to push {}: {}", ip, e);
                }
            }
            drop(permit);
        }));
    }

    for h in handles {
        let _ = h.await;
    }
}

pub async fn update_field(conn: &mut ConnectionManager, task_id: Uuid, field: &str, value: bool) {
    let _: () = conn
        .set_ex(state_key(task_id, field), value, TTL)
        .await
        .unwrap();
}

pub async fn assign(
    conn: &mut ConnectionManager,
    task_id: Uuid,
    agent_id: Uuid,
    target_count: u32,
) {
    let _: () = conn
        .set_ex(task_agent_key(task_id), agent_id.to_string(), TTL)
        .await
        .unwrap();
    let _: () = conn
        .sadd(agent_tasks_key(agent_id), task_id.to_string())
        .await
        .unwrap();
    set_task_target_count(conn, task_id, target_count, TTL).await;
    add_agent_targets(conn, agent_id, target_count, TTL).await;
}

pub async fn count_agent_tasks(conn: &mut ConnectionManager, agent_id: Uuid) -> u32 {
    conn.scard(agent_tasks_key(agent_id)).await.unwrap_or(0)
}

pub async fn count_agent_targets(conn: &mut ConnectionManager, agent_id: Uuid) -> u32 {
    let key = agent_target_count_key(agent_id);
    let val: Option<u32> = conn.get(&key).await.unwrap_or(None);
    val.unwrap_or(0)
}

pub async fn add_agent_targets(conn: &mut ConnectionManager, agent_id: Uuid, count: u32, ttl: u64) {
    let key = agent_target_count_key(agent_id);
    if count > 0 {
        let _ = redis::cmd("INCRBY")
            .arg(&key)
            .arg(count)
            .query_async::<()>(conn)
            .await;
        let _ = conn.expire::<_, ()>(key, ttl as i64).await;
    }
}

pub async fn sub_agent_targets(conn: &mut ConnectionManager, agent_id: Uuid, count: u32) {
    let key = agent_target_count_key(agent_id);
    if count > 0 {
        let _ = redis::cmd("DECRBY")
            .arg(&key)
            .arg(count)
            .query_async::<()>(conn)
            .await;
    }
}

pub async fn set_task_target_count(
    conn: &mut ConnectionManager,
    task_id: Uuid,
    count: u32,
    ttl: u64,
) {
    let _: () = conn
        .set_ex(task_target_count_key(task_id), count, ttl)
        .await
        .unwrap_or_default();
}

pub async fn get_task_target_count(conn: &mut ConnectionManager, task_id: Uuid) -> u32 {
    let val: Option<u32> = conn
        .get(task_target_count_key(task_id))
        .await
        .unwrap_or(None);
    val.unwrap_or(0)
}

pub async fn is_all_done(conn: &mut ConnectionManager, task_id: Uuid) -> bool {
    let state = TaskState::default();
    for key in state.keys() {
        let val: Option<bool> = conn.get(state_key(task_id, key)).await.unwrap_or(None);
        match val {
            Some(false) => return false,
            _ => continue,
        }
    }
    true
}

pub async fn cleanup(conn: &mut ConnectionManager, task_id: Uuid) {
    let agent_id: Option<String> = conn.get(task_agent_key(task_id)).await.unwrap_or(None);
    if let Some(aid_str) = &agent_id {
        if let Ok(aid) = Uuid::parse_str(aid_str) {
            let _: () = conn
                .srem(agent_tasks_key(aid), task_id.to_string())
                .await
                .unwrap();
            let tc = get_task_target_count(conn, task_id).await;
            sub_agent_targets(conn, aid, tc).await;
        }
    }

    let _: () = conn
        .srem("distribute:pending", task_id.to_string())
        .await
        .unwrap_or_default();

    let state = TaskState::default();
    for key in state.keys() {
        let _: () = conn.del(state_key(task_id, key)).await.unwrap();
    }
    let _: () = conn.del(task_targets_key(task_id)).await.unwrap();
    let _: () = conn.del(task_agent_key(task_id)).await.unwrap();
    let _: () = conn.del(task_target_count_key(task_id)).await.unwrap();
}

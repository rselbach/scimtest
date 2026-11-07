use super::*;
use rusqlite::OptionalExtension;

pub(super) struct Choice {
    pub port: u16,
    pub pinned: bool,
    ambient: bool,
}
pub(super) fn resolve(flag: u16, scimtest: &str, ambient: &str, last: &str) -> Result<Choice> {
    if flag != 0 {
        return Ok(Choice {
            port: flag,
            pinned: true,
            ambient: false,
        });
    }
    for (value, ambient) in [(scimtest, false), (ambient, true)] {
        if !value.trim().is_empty() {
            return Ok(Choice {
                port: options::parse_port(value).map_err(anyhow::Error::msg)?,
                pinned: true,
                ambient,
            });
        }
    }
    let port = options::parse_port(last).map_err(anyhow::Error::msg)?;
    Ok(Choice {
        port: if port == 0 { 8080 } else { port },
        pinned: false,
        ambient: false,
    })
}
pub(super) fn bind(choice: &Choice) -> Result<std::net::TcpListener> {
    if choice.ambient {
        eprintln!(
            "Using port {} from PORT; set SCIMTEST_PORT or pass --port to silence this",
            choice.port
        );
    }
    let end = if choice.pinned {
        choice.port
    } else {
        choice.port.saturating_add(100)
    };
    for port in choice.port..=end {
        match std::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)) {
            Ok(listener) => return Ok(listener),
            Err(error) if !choice.pinned && error.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(error) => return Err(error).with_context(|| format!("Listen on 127.0.0.1:{port}")),
        }
    }
    anyhow::bail!(
        "no available port from {} through {end} on 127.0.0.1; pass --port to choose one",
        choice.port
    )
}
impl Store {
    pub(super) fn last_admin_port(&self) -> Result<String, crate::Error> {
        let connection = self.connection()?;
        Ok(connection
            .query_row(
                "SELECT value FROM config WHERE key = 'last_admin_port'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .unwrap_or_default())
    }
    pub(super) fn remember_admin_port(&self, port: u16) -> Result<(), crate::Error> {
        self.connection()?.execute("INSERT INTO config(key,value) VALUES ('last_admin_port',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[port.to_string()])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn port_priority_and_fallback_match_go() {
        for (flag, scimtest, ambient, last, port, pinned) in [
            (9001, "9002", "9003", "9004", 9001, true),
            (0, "9002", "9003", "9004", 9002, true),
            (0, "", "9003", "9004", 9003, true),
            (0, "", "", "9004", 9004, false),
            (0, " ", " ", " ", 8080, false),
        ] {
            let choice = resolve(flag, scimtest, ambient, last).unwrap();
            assert_eq!((choice.port, choice.pinned), (port, pinned));
        }
        let mut pair = None;
        for _ in 0..100 {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            if port == 65535 {
                continue;
            }
            if let Ok(next) = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port + 1)) {
                pair = Some((listener, next, port));
                break;
            }
        }
        let (occupied, next, port) = pair.unwrap();
        drop(next);
        assert!(
            bind(&Choice {
                port,
                pinned: true,
                ambient: false
            })
            .is_err()
        );
        let listener = bind(&Choice {
            port,
            pinned: false,
            ambient: false,
        })
        .unwrap();
        let bound_port = listener.local_addr().unwrap().port();
        assert!(bound_port > port && bound_port <= port.saturating_add(100));
        drop(occupied);
    }
}

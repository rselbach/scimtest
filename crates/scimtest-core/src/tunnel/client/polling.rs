use super::*;
use serde::Deserialize;

#[derive(Deserialize)]
struct Status {
    status: String,
    #[serde(default)]
    error: String,
}
impl Client {
    pub(super) async fn poll_enrollment(&mut self, enrollment: &Enrollment) -> Result<(), Failure> {
        loop {
            let result = tokio::select! {
                _=self.cancellation.cancelled()=>return Ok(()),
                result=self.fetch_enrollment(enrollment)=>result,
            };
            match result {
                Ok(status) if status.status == "approved" => {
                    self.grant = enrollment.device_code.clone();
                    return Ok(());
                }
                Ok(status) if status.status == "pending" => {}
                Ok(status) => {
                    let error = if status.error.trim().is_empty() {
                        format!("unexpected status {:?}", status.status)
                    } else {
                        status.error.trim().into()
                    };
                    return Err(Failure::terminal(format!(
                        "tunnel enrollment failed: {error}"
                    )));
                }
                Err(error) if error.terminal => return Err(error),
                Err(error) => eprintln!("Enrollment status request failed; retrying: {error}"),
            }
            tokio::select! { _=self.cancellation.cancelled()=>return Ok(()), _=tokio::time::sleep(enrollment.poll_interval)=>{} }
        }
    }
    async fn fetch_enrollment(&self, enrollment: &Enrollment) -> Result<Status, Failure> {
        let response = self
            .http
            .post(enrollment.status_url.clone())
            .header("Accept", "application/json")
            .header("Cache-Control", "no-store")
            .bearer_auth(&enrollment.device_code)
            .timeout(Duration::from_secs(15))
            .send()
            .await
            .map_err(|error| Failure::retry(format!("get enrollment status: {error}")))?;
        let status = response.status();
        if status.as_u16() == 429 || status.is_server_error() {
            return Err(Failure::retry(format!(
                "get enrollment status: HTTP {status}"
            )));
        }
        if !status.is_success() {
            return Err(Failure::terminal(format!(
                "get enrollment status: HTTP {status}"
            )));
        }
        let bytes = forward::read_response(response, 64 << 10)
            .await
            .map_err(|error| Failure::terminal(format!("decode enrollment status: {error}")))?;
        serde_json::from_slice(&bytes)
            .map_err(|error| Failure::terminal(format!("decode enrollment status: {error}")))
    }
}

//! `docspring support watch`: waits until a support ticket changes (DocSpring's team replied, or its status changed),
//! then prints the ticket. For an AI agent to leave running in a background shell: it has no inbox to be told in.

use std::time::{Duration, Instant};

use clap::Args;
use docspring::Api;
use serde::Deserialize;

use crate::errors::{describe, CliError};
use crate::runner::{CommandResult, Runner};
use crate::session;

/// Wait until a support ticket changes, then print it
///
/// Waits for a reply from DocSpring's team or a change of status, up to --timeout, then prints the ticket with its new
/// messages, as `support get-ticket` does. A ticket that already has unread replies is printed at once. Run it in the
/// background after opening a ticket. It polls the ticket's watch URL, which says only that the ticket changed.
#[derive(Debug, Args)]
pub struct WatchArgs {
    /// The support ticket's ID
    #[arg(value_parser = crate::runner::path_segment)]
    ticket_id: String,
    /// How long to wait for a change, in seconds
    #[arg(long, default_value_t = 3600, value_name = "SECONDS")]
    timeout: u64,
}

/// What the watch URL answers: nothing about the ticket but that it changed
#[derive(Debug, Deserialize)]
struct Watch {
    updated_at: String,
    /// Whether this host holds a request open until the ticket changes (`?wait=`): the sync API host does
    #[serde(default)]
    long_poll: bool,
    /// The fewest seconds between polls
    #[serde(default)]
    min_interval_seconds: u64,
}

/// The longest the watch URL holds a request open
const WAIT_SECONDS: u64 = 60;

pub async fn watch(runner: &Runner, args: WatchArgs) -> CommandResult {
    let timeout = Duration::from_secs(args.timeout);
    let started = Instant::now();
    let ticket = get_ticket(runner, &args.ticket_id).await?;
    if ticket.unread_count > 0 {
        return print(runner, &ticket);
    }

    let http = session::http_client()?;
    // The first poll has no ETag, so it answers at once with the ticket's state now
    let (mut etag, state) = match poll(&http, &ticket.watch_url, None, 0).await? {
        Poll::Changed(etag, state) => (etag, state),
        Poll::Unchanged => return Err(CliError::api("The ticket's watch URL didn't answer. Run the command again.")),
        Poll::Unreachable(why) => {
            return Err(CliError::api(format!(
                "The ticket's watch URL didn't answer ({why}). Run the command again."
            )));
        }
    };
    // The ticket changed between the two requests
    if chrono::DateTime::parse_from_rfc3339(&state.updated_at).is_ok_and(|updated_at| updated_at > ticket.updated_at) {
        return print(runner, &get_ticket(runner, &args.ticket_id).await?);
    }
    runner.notice(&format!("Waiting for a change to {} (up to {} seconds)", ticket.id, args.timeout));

    let interval = Duration::from_secs(state.min_interval_seconds.max(1));
    loop {
        let left = timeout.saturating_sub(started.elapsed());
        if left.is_zero() {
            return Err(unchanged(&ticket.id, args.timeout));
        }
        let wait = if state.long_poll { WAIT_SECONDS.min(left.as_secs()) } else { 0 };
        let asked = Instant::now();
        // The poll gets only the time that's left, and a little longer than it asked the server to wait
        let answer = match tokio::time::timeout(
            left.min(Duration::from_secs(wait + 30)),
            poll(&http, &ticket.watch_url, Some(&etag), wait),
        )
        .await
        {
            Ok(answer) => answer?,
            Err(_) if left <= Duration::from_secs(wait + 30) => return Err(unchanged(&ticket.id, args.timeout)),
            Err(_) => Poll::Unchanged,
        };
        if let Poll::Changed(new_etag, _) = answer {
            let changed = get_ticket(runner, &args.ticket_id).await?;
            // A change that isn't news (the ticket was read somewhere else) keeps waiting
            if changed.unread_count > 0 || changed.status != ticket.status {
                return print(runner, &changed);
            }
            etag = new_etag;
        }
        // A host that answers at once, or a long poll that came back early, is asked again no sooner than it allows
        let pause = interval.saturating_sub(asked.elapsed()).min(timeout.saturating_sub(started.elapsed()));
        tokio::time::sleep(pause).await;
    }
}

enum Poll {
    /// The state and its ETag
    Changed(String, Watch),
    Unchanged,
    /// The request didn't get through, or the server failed: why, for when it's the first poll
    Unreachable(String),
}

/// Asks the watch URL once. It takes no credentials: the URL is the secret.
async fn poll(http: &reqwest::Client, url: &str, etag: Option<&str>, wait: u64) -> Result<Poll, CliError> {
    let failed = |error: reqwest::Error| CliError::api(format!("Couldn't reach the ticket's watch URL: {}", describe(&error)));
    let mut request = http.get(url);
    if wait > 0 {
        request = request.query(&[("wait", wait)]);
    }
    if let Some(etag) = etag {
        request = request.header(reqwest::header::IF_NONE_MATCH, etag);
    }
    // A wait of up to an hour outlives a deploy of the API, a dropped connection and a laptop that slept: a request
    // that didn't get through, or a server error, is asked again after the usual pause
    let response = match request.send().await {
        Ok(response) => response,
        Err(error) => return Ok(Poll::Unreachable(describe(&error))),
    };
    let status = response.status();
    if status.is_server_error() {
        return Ok(Poll::Unreachable(format!("it answered {status}")));
    }
    if status == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(Poll::Unchanged);
    }
    // Too many polls: wait and ask again
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Ok(Poll::Unchanged);
    }
    if !status.is_success() {
        return Err(CliError::api(format!("The ticket's watch URL answered {status}")));
    }
    let etag = response
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .ok_or_else(|| CliError::api("The ticket's watch URL answered without an ETag"))?;
    let state = response.json().await.map_err(failed)?;
    Ok(Poll::Changed(etag, state))
}

async fn get_ticket(runner: &Runner, id: &str) -> Result<docspring::models::SupportTicket, CliError> {
    let params = docspring::GetSupportTicketParams::builder().ticket_id(id.to_owned()).build();
    runner.client().await?.get_support_ticket(params).await.map_err(CliError::from_sdk)
}

fn print(runner: &Runner, ticket: &docspring::models::SupportTicket) -> CommandResult {
    let value = serde_json::to_value(ticket).map_err(|error| CliError::api(format!("Couldn't print the ticket: {error}")))?;
    runner.print(&value, None);
    Ok(())
}

fn unchanged(id: &str, seconds: u64) -> CliError {
    CliError::api(format!(
        "Support ticket {id} didn't change in {seconds} seconds. Run `docspring support watch {id}` again to keep waiting."
    ))
}

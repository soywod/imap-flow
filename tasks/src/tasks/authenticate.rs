use std::borrow::Cow;

use imap_types::{
    auth::{AuthMechanism, AuthenticateData},
    command::CommandBody,
    core::Vec1,
    response::{Capability, Code, CommandContinuationRequest, Data, StatusBody, StatusKind},
    secret::Secret,
};
use tracing::warn;

use crate::{tasks::TaskError, Task};

#[derive(Clone, Debug)]
pub struct AuthenticateTask {
    /// Authentication mechanism.
    ///
    /// Note: Currently only used for `AUTH={PLAIN,XOAUTH2,OAUTHBEARER}`
    ///       Invariants need to be enforced through constructors.
    mechanism: AuthMechanism<'static>,

    /// Static authentication data.
    ///
    /// Note: Currently only used for `AUTH={PLAIN,XOAUTH2,OAUTHBEARER}`
    line: Option<Vec<u8>>,

    /// Does the server support SASL's initial response?
    ir: bool,

    output: Option<Vec1<Capability<'static>>>,
}

impl Task for AuthenticateTask {
    type Output = Result<Option<Vec1<Capability<'static>>>, TaskError>;

    fn command_body(&self) -> CommandBody<'static> {
        CommandBody::Authenticate {
            mechanism: self.mechanism.clone(),
            initial_response: if self.ir {
                // TODO: command_body must only be called once... hm...
                Some(Secret::new(Cow::Owned(self.line.clone().unwrap())))
            } else {
                None
            },
        }
    }

    // Capabilities may (unfortunately) be found in a data response.
    // See https://github.com/modern-email/defects/issues/18
    fn process_data(&mut self, data: Data<'static>) -> Option<Data<'static>> {
        if let Data::Capability(capabilities) = data {
            self.output = Some(capabilities);
            None
        } else {
            Some(data)
        }
    }

    fn process_continuation_request_authenticate(
        &mut self,
        continuation: CommandContinuationRequest<'static>,
    ) -> Result<AuthenticateData<'static>, CommandContinuationRequest<'static>> {
        match self.mechanism {
            // See https://developers.google.com/gmail/imap/xoauth2-protocol
            AuthMechanism::XOAuth2 => {
                // SASL-IR is supported, so line was already sent.
                // Therefore, the current continuation request indicates an error.
                //
                // > The client sends an empty response ("\r\n") to
                // > the challenge containing the error message.
                if self.ir {
                    match continuation {
                        CommandContinuationRequest::Basic(basic) => {
                            let text = basic.text();
                            warn!("error during XOAUTH2 auth: {text}")
                        }
                        CommandContinuationRequest::Base64(data) => {
                            let text = String::from_utf8_lossy(data.as_ref());
                            warn!("error during XOAUTH2 auth: {text}")
                        }
                    }

                    Ok(AuthenticateData::r#continue(vec![]))
                } else
                // SASL-IR is not supported, so the line needs to be sent.
                if let Some(line) = self.line.take() {
                    Ok(AuthenticateData::r#continue(line))
                } else {
                    Ok(AuthenticateData::Cancel)
                }
            }
            // Default behaviour, may evolve depending on mechanisms.
            _ => {
                if self.ir {
                    Ok(AuthenticateData::Cancel)
                } else if let Some(line) = self.line.take() {
                    Ok(AuthenticateData::r#continue(line))
                } else {
                    Ok(AuthenticateData::Cancel)
                }
            }
        }
    }

    fn process_tagged(self, status_body: StatusBody<'static>) -> Self::Output {
        match status_body.kind {
            StatusKind::Ok => Ok(self.output.or(
                // Capabilities may be found in the status body of tagged response.
                if let Some(Code::Capability(capabilities)) = status_body.code {
                    Some(capabilities)
                } else {
                    None
                },
            )),
            StatusKind::No => Err(TaskError::UnexpectedNoResponse(status_body)),
            StatusKind::Bad => Err(TaskError::UnexpectedBadResponse(status_body)),
        }
    }
}

impl AuthenticateTask {
    pub fn plain(login: &str, passwd: &str, ir: bool) -> Self {
        let line = format!("\x00{login}\x00{passwd}");

        Self {
            mechanism: AuthMechanism::Plain,
            line: Some(line.into_bytes()),
            ir,
            output: None,
        }
    }

    pub fn xoauth2(user: &str, token: &str, ir: bool) -> Self {
        let line = format!("user={user}\x01auth=Bearer {token}\x01\x01");

        Self {
            mechanism: AuthMechanism::XOAuth2,
            line: Some(line.into_bytes()),
            ir,
            output: None,
        }
    }

    pub fn oauthbearer(a: &str, host: &str, port: u16, token: &str, ir: bool) -> Self {
        let line = format!("n,a={a},\x01host={host}\x01port={port}\x01auth=Bearer {token}\x01\x01");

        Self {
            mechanism: AuthMechanism::XOAuth2,
            line: Some(line.into_bytes()),
            ir,
            output: None,
        }
    }
}

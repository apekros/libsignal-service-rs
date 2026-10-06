use crate::utils::serde_base64_url_safe_no_pad;
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use libsignal_core::{Aci, ServiceIdKind};
use rand::RngCore as _;
use reqwest::Method;
use serde::Serialize;

use crate::content::ServiceError;

use super::{Identified, SignalWebSocket, Unidentified};

impl SignalWebSocket<Unidentified> {
    pub async fn look_up_username(
        &mut self,
        username: &usernames::Username,
    ) -> Result<Option<Aci>, ServiceError> {
        self.look_up_username_hash(&username.hash()).await
    }

    // Based on libsignal-net
    pub async fn look_up_username_hash(
        &mut self,
        hash: &[u8],
    ) -> Result<Option<Aci>, ServiceError> {
        #[derive(serde::Deserialize)]
        struct UsernameHashResponse {
            uuid: String,
        }

        let response = self
            .http_request(
                Method::GET,
                format!(
                    "/v1/accounts/username_hash/{}",
                    BASE64_URL_SAFE_NO_PAD.encode(hash)
                ),
            )?
            .send()
            .await?;

        if response.status() == 404 {
            tracing::debug!("username not found");
            return Ok(None);
        }

        let result: UsernameHashResponse =
            response.service_error_for_status().await?.json().await?;

        Ok(Some(
            Aci::parse_from_service_id_string(&result.uuid).ok_or_else(
                || ServiceError::InvalidAddressType(ServiceIdKind::Aci),
            )?,
        ))
    }

    /// Looks up the encrypted username stored at a username link handle and
    /// decrypts it.
    ///
    /// `link` must be a full `https://signal.me/#eu/<payload>` URL. The payload
    /// is the URL-safe base64 encoding of the 32-byte link entropy followed by
    /// the 16-byte link handle UUID.
    // Based on libsignal-net
    pub async fn look_up_username_link(
        &mut self,
        link: &url::Url,
    ) -> Result<Option<usernames::Username>, ServiceError> {
        #[derive(serde::Deserialize)]
        struct UsernameLinkResponse {
            #[serde(rename = "usernameLinkEncryptedValue")]
            #[serde(with = "serde_base64_url_safe_no_pad")]
            encrypted_username: Vec<u8>,
        }

        let (uuid, entropy) = parse_username_link(link)?;

        let response = self
            .http_request(
                Method::GET,
                format!("/v1/accounts/username_link/{uuid}"),
            )?
            .send()
            .await?;

        if response.status() == 404 {
            tracing::debug!("username link not found");
            return Ok(None);
        }

        let result: UsernameLinkResponse =
            response.service_error_for_status().await?.json().await?;

        let plaintext_username =
            usernames::decrypt_username(&entropy, &result.encrypted_username)
                .map_err(|error| {
                tracing::error!(%error, "undecryptable username");
                ServiceError::InvalidFrame {
                    reason: "undecryptable username link",
                }
            })?;

        let validated_username = usernames::Username::new(&plaintext_username).map_err(|e| {
            // Exhaustively match UsernameError to make sure there's nothing we shouldn't log.
            #[allow(clippy::let_unit_value)]
            let _username_error_carries_no_information_that_would_be_bad_to_log = match e {
                usernames::UsernameError::MissingSeparator
                | usernames::UsernameError::NicknameCannotBeEmpty
                | usernames::UsernameError::NicknameCannotStartWithDigit
                | usernames::UsernameError::BadNicknameCharacter
                | usernames::UsernameError::NicknameTooShort
                | usernames::UsernameError::NicknameTooLong
                | usernames::UsernameError::DiscriminatorCannotBeEmpty
                | usernames::UsernameError::DiscriminatorCannotBeZero
                | usernames::UsernameError::DiscriminatorCannotBeSingleDigit
                | usernames::UsernameError::DiscriminatorCannotHaveLeadingZeros
                | usernames::UsernameError::BadDiscriminatorCharacter
                | usernames::UsernameError::DiscriminatorTooLarge => {}
            };
            tracing::warn!(error=%e, "username link decrypted to an invalid username");
            tracing::debug!(error=%e,
                "username link decrypted to '{plaintext_username}', which is not valid"
            );
            // The user didn't ever type this username, so the precise way in which it's invalid
            // isn't important. Treat this equivalent to having found garbage data in the link. This
            // simplifies error handling for callers.
            ServiceError::InvalidFrame {
                reason: "undecryptable username link",
            }
        })?;

        Ok(Some(validated_username))
    }
}

/// Splits a username link into its link handle UUID and link entropy.
///
/// `link` must be a full `https://signal.me/#eu/<payload>` URL. The payload is
/// URL-safe base64 (no padding) of the 32-byte entropy followed by the 16-byte
/// handle UUID.
fn parse_username_link(
    link: &url::Url,
) -> Result<
    (
        uuid::Uuid,
        [u8; usernames::constants::USERNAME_LINK_ENTROPY_SIZE],
    ),
    ServiceError,
> {
    if link.scheme() != "https" || link.host_str() != Some("signal.me") {
        return Err(ServiceError::InvalidFrame {
            reason: "username link base is not https://signal.me",
        });
    }

    let fragment =
        link.fragment().ok_or_else(|| ServiceError::InvalidFrame {
            reason: "username link missing fragment",
        })?;
    let mut segments = fragment.split('/');
    if segments.next() != Some("eu") {
        return Err(ServiceError::InvalidFrame {
            reason: "username link must start with #eu/",
        });
    }
    let payload =
        segments.next().ok_or_else(|| ServiceError::InvalidFrame {
            reason: "username link payload missing",
        })?;
    if segments.next().is_some() {
        return Err(ServiceError::InvalidFrame {
            reason: "username link has extra path segments",
        });
    }

    let bytes = BASE64_URL_SAFE_NO_PAD.decode(payload)?;

    let (entropy, rest) = bytes
        .split_first_chunk::<{ usernames::constants::USERNAME_LINK_ENTROPY_SIZE }>()
        .ok_or_else(|| ServiceError::InvalidFrame {
            reason: "username link payload shorter than entropy",
        })?;

    let handle_uuid = uuid::Uuid::from_slice(rest).map_err(|_| {
        ServiceError::InvalidFrame {
            reason: "username link payload missing handle UUID",
        }
    })?;

    Ok((handle_uuid, *entropy))
}

impl SignalWebSocket<Identified> {
    /// Sets the account's username link to encrypt `username` and returns the
    /// shareable `https://signal.me/#eu/...` link.
    ///
    /// Generates fresh entropy and, unless `keep_link_handle` is `true` and the
    /// account already has a link handle, a fresh server-assigned handle.
    // Based on libsignal-net
    pub async fn set_username_link(
        &mut self,
        username: &usernames::Username,
        keep_link_handle: bool,
    ) -> Result<url::Url, ServiceError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct SetUsernameLinkRequest {
            #[serde(with = "serde_base64_url_safe_no_pad")]
            username_link_encrypted_value: Vec<u8>,
            keep_link_handle: bool,
        }

        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct UsernameLinkHandleResponse {
            username_link_handle: uuid::Uuid,
        }

        let (entropy, ciphertext) = usernames::create_for_username(
            &mut rand::rng(),
            username.to_string(),
            None,
        )
        .map_err(|_e| ServiceError::InvalidFrame {
            reason: "username too long to encrypt",
        })?;

        let response = self
            .http_request(Method::PUT, "/v1/accounts/username_link")?
            .send_json(SetUsernameLinkRequest {
                username_link_encrypted_value: ciphertext,
                keep_link_handle,
            })
            .await?
            .service_error_for_status()
            .await?;

        let result: UsernameLinkHandleResponse = response.json().await?;

        Ok(generate_username_link(
            result.username_link_handle,
            &entropy,
        ))
    }
}

/// The most username candidates the server accepts in one reservation request.
pub const MAX_USERNAME_CANDIDATES: usize = 20;

/// A username the server has reserved for this account, but not yet confirmed.
///
/// Only [SignalWebSocket::reserve_username] creates these, and
/// [SignalWebSocket::confirm_username] consumes them, so you can't confirm
/// something the server never reserved for you.
pub struct UsernameReservation {
    username: usernames::Username,
}

impl UsernameReservation {
    pub fn username(&self) -> &usernames::Username {
        &self.username
    }
}

/// A username that now belongs to this account.
pub struct ConfirmedUsername {
    pub username: usernames::Username,
    /// Shareable `https://signal.me/#eu/...` link, if the server assigned a
    /// link handle.
    pub link: Option<url::Url>,
}

impl SignalWebSocket<Identified> {
    /// Reserves the first available username out of `candidates`, which are
    /// tried in order. Returns `None` if every candidate is taken.
    ///
    /// Use [usernames::Username::candidates_from] to generate candidates for a
    /// nickname with random discriminators, the way the official clients do.
    /// A reservation only holds for a few minutes, so confirm it with
    /// [Self::confirm_username] straight away.
    // Based on Signal-Server's AccountController::reserveUsernameHash
    pub async fn reserve_username(
        &mut self,
        candidates: Vec<usernames::Username>,
    ) -> Result<Option<UsernameReservation>, ServiceError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct ReserveUsernameHashRequest {
            username_hashes: Vec<String>,
        }

        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct ReserveUsernameHashResponse {
            #[serde(with = "serde_base64_url_safe_no_pad")]
            username_hash: Vec<u8>,
        }

        if candidates.is_empty() || candidates.len() > MAX_USERNAME_CANDIDATES {
            return Err(ServiceError::InvalidFrame {
                reason: "username reservation needs 1 to 20 candidates",
            });
        }

        let username_hashes = candidates
            .iter()
            .map(|candidate| BASE64_URL_SAFE_NO_PAD.encode(candidate.hash()))
            .collect();

        let response = self
            .http_request(Method::PUT, "/v1/accounts/username_hash/reserve")?
            .send_json(ReserveUsernameHashRequest { username_hashes })
            .await?;

        // The generic status handling reads 409 as mismatched devices, but
        // here it means every candidate is taken.
        if response.status() == 409 {
            return Ok(None);
        }

        let result: ReserveUsernameHashResponse =
            response.service_error_for_status().await?.json().await?;

        let username = candidates
            .into_iter()
            .find(|candidate| candidate.hash()[..] == result.username_hash[..])
            .ok_or(ServiceError::InvalidFrame {
                reason: "server reserved a username hash we did not ask for",
            })?;

        Ok(Some(UsernameReservation { username }))
    }

    /// Makes a reserved username this account's username, replacing any
    /// previous one, and sets up a fresh username link for it.
    ///
    /// Returns `None` if the reservation is gone, either because it expired
    /// or because someone else took the username in the meantime. Reserve
    /// again in that case.
    // Based on Signal-Server's AccountController::confirmUsernameHash
    pub async fn confirm_username(
        &mut self,
        reservation: UsernameReservation,
    ) -> Result<Option<ConfirmedUsername>, ServiceError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct ConfirmUsernameHashRequest {
            #[serde(with = "serde_base64_url_safe_no_pad")]
            username_hash: [u8; 32],
            #[serde(with = "serde_base64_url_safe_no_pad")]
            zk_proof: Vec<u8>,
            #[serde(with = "serde_base64_url_safe_no_pad")]
            encrypted_username: Vec<u8>,
        }

        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct UsernameHashResponse {
            username_link_handle: Option<uuid::Uuid>,
        }

        let UsernameReservation { username } = reservation;

        let mut randomness = [0u8; 32];
        rand::rng().fill_bytes(&mut randomness);
        let zk_proof = username.proof(&randomness).map_err(|_| {
            ServiceError::InvalidFrame {
                reason: "failed to prove username hash",
            }
        })?;

        let (entropy, encrypted_username) = usernames::create_for_username(
            &mut rand::rng(),
            username.to_string(),
            None,
        )
        .map_err(|_| ServiceError::InvalidFrame {
            reason: "username too long to encrypt",
        })?;

        let response = self
            .http_request(Method::PUT, "/v1/accounts/username_hash/confirm")?
            .send_json(ConfirmUsernameHashRequest {
                username_hash: username.hash(),
                zk_proof,
                encrypted_username,
            })
            .await?;

        // 409: no matching reservation. 410: the username was taken after all.
        // The generic status handling would misread both as device errors.
        if response.status() == 409 || response.status() == 410 {
            return Ok(None);
        }

        let result: UsernameHashResponse =
            response.service_error_for_status().await?.json().await?;

        Ok(Some(ConfirmedUsername {
            link: result
                .username_link_handle
                .map(|handle| generate_username_link(handle, &entropy)),
            username,
        }))
    }

    /// Removes this account's username and username link. Succeeds if there
    /// was no username to begin with.
    // Based on Signal-Server's AccountController::deleteUsernameHash
    pub async fn delete_username(&mut self) -> Result<(), ServiceError> {
        self.http_request(Method::DELETE, "/v1/accounts/username_hash")?
            .send()
            .await?
            .service_error_for_status()
            .await?;
        Ok(())
    }
}

/// Builds the `https://signal.me/#eu/<base64url>` link from its parts.
///
/// `entropy` is the 32-byte link entropy; `handle` is the server-assigned
/// link handle UUID. The payload is the URL-safe base64 (no padding) of
/// `entropy || handle`.
pub fn generate_username_link(
    handle: uuid::Uuid,
    entropy: &[u8; usernames::constants::USERNAME_LINK_ENTROPY_SIZE],
) -> url::Url {
    let mut payload = entropy.to_vec();
    payload.extend_from_slice(handle.as_bytes());
    let mut result = String::from("https://signal.me/#eu/");
    BASE64_URL_SAFE_NO_PAD.encode_string(&payload, &mut result);

    url::Url::parse(&result).expect("can only generate valid URLs")
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn generate_and_parse_link_round_trip() {
        let entropy = [0x42; usernames::constants::USERNAME_LINK_ENTROPY_SIZE];
        let handle = uuid::uuid!("9d0652a3-dcc3-4d11-975f-74d61598733f");
        // deliberately chosen to round-trip cleanly through URL-safe base64
        let link = generate_username_link(handle, &entropy);
        assert!(link.as_str().starts_with("https://signal.me/#eu/"));

        let (parsed_handle, parsed_entropy) =
            parse_username_link(&link).unwrap();
        assert_eq!(parsed_handle, handle);
        assert_eq!(parsed_entropy, entropy);
    }

    #[test]
    fn parse_link_rejects_wrong_base() {
        let entropy = [0x42; usernames::constants::USERNAME_LINK_ENTROPY_SIZE];
        let handle = uuid::uuid!("9d0652a3-dcc3-4d11-975f-74d61598733f");
        let bad_link = generate_username_link(handle, &entropy)
            .to_string()
            .replace("signal.me", "example.com");
        let bad_link = url::Url::parse(&bad_link).unwrap();
        assert!(parse_username_link(&bad_link).is_err());
    }

    #[test]
    fn parse_link_rejects_missing_eu_marker() {
        let bad_link = url::Url::parse(
            "https://signal.me/#foo/R_rHg5IQLE60Qad5l8rV-6x2TMcVnDYvOV-igYXJj6GK1NuNeE9LKI3V_VZ8IH2p",
        )
        .unwrap();
        assert!(parse_username_link(&bad_link).is_err());
    }

    #[test]
    fn parse_link_rejects_extra_fragment_segments() {
        let bad_link =
            url::Url::parse("https://signal.me/#eu/payload/extra").unwrap();
        assert!(parse_username_link(&bad_link).is_err());
    }
}

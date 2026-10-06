use libsignal_protocol::Aci;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use zkgroup::profiles::{ProfileKeyCommitment, ProfileKeyVersion};

use crate::{
    content::ServiceError,
    push_service::{AttachmentV2UploadAttributes, AvatarWrite},
    utils::{serde_base64, serde_optional_base64},
    websocket::{self, account::DeviceCapabilities, SignalWebSocket},
};

/// A donation badge returned by the server on profile fetch.
///
/// Mirrors the JSON shape of Signal-Android's `SignalServiceProfile.Badge`.
/// Display metadata is render-ready (name, description, sprites6 image URLs).
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Badge {
    /// Server catalog id (e.g. "BOOSTING").
    #[serde(default)]
    pub id: String,
    /// Badge category string.
    #[serde(default)]
    pub category: String,
    /// Render-ready display name.
    #[serde(default)]
    pub name: String,
    /// Render-ready description.
    #[serde(default)]
    pub description: String,
    /// Sprite image URLs (density-tagged).
    #[serde(default)]
    pub sprites6: Vec<String>,
    /// Expiration epoch millis. Java sends this as BigDecimal.
    #[serde(default)]
    pub expiration: Option<f64>,
    /// Whether the badge is displayed on the profile.
    #[serde(default)]
    pub visible: bool,
    /// Duration badge is valid for, in seconds.
    #[serde(default)]
    pub duration: i64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignalServiceProfile {
    #[serde(default, with = "serde_optional_base64")]
    pub identity_key: Option<Vec<u8>>,
    #[serde(default, with = "serde_optional_base64")]
    pub name: Option<Vec<u8>>,
    #[serde(default, with = "serde_optional_base64")]
    pub about: Option<Vec<u8>>,
    #[serde(default, with = "serde_optional_base64")]
    pub about_emoji: Option<Vec<u8>>,

    // TODO: not sure whether this is via optional_base64
    // #[serde(default, with = "serde_optional_base64")]
    // pub payment_address: Option<Vec<u8>>,
    pub avatar: Option<String>,
    pub unidentified_access: Option<String>,

    #[serde(default)]
    pub unrestricted_unidentified_access: bool,

    pub capabilities: DeviceCapabilities,

    /// Donation badges the server reports for this profile.
    #[serde(default)]
    pub badges: Vec<Badge>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SignalServiceProfileWrite<'s> {
    /// Hex-encoded
    version: &'s str,
    #[serde(with = "serde_base64")]
    name: &'s [u8],
    #[serde(with = "serde_base64")]
    about: &'s [u8],
    #[serde(with = "serde_base64")]
    about_emoji: &'s [u8],
    avatar: bool,
    same_avatar: bool,
    #[serde(with = "serde_base64")]
    commitment: &'s [u8],
}

impl SignalWebSocket<websocket::Identified> {
    pub async fn retrieve_profile_by_id(
        &mut self,
        address: Aci,
        profile_key: Option<zkgroup::profiles::ProfileKey>,
    ) -> Result<SignalServiceProfile, ServiceError> {
        let path = if let Some(key) = profile_key {
            let version =
                bincode::serialize(&key.get_profile_key_version(address))?;
            let version = std::str::from_utf8(&version)
                .expect("hex encoded profile key version");
            format!("/v1/profile/{}/{}", address.service_id_string(), version)
        } else {
            format!("/v1/profile/{}", address.service_id_string())
        };
        // TODO: set locale to en_US
        self.http_request(Method::GET, path)?
            .send()
            .await?
            .service_error_for_status()
            .await?
            .json()
            .await
    }

    /// Writes a profile and returns the avatar URL, if one was provided.
    ///
    /// The name, about and emoji fields are encrypted with an [`ProfileCipher`][struct@crate::profile_cipher::ProfileCipher].
    /// So is a [AvatarWrite::NewAvatar], using
    /// [`ProfileCipher::encrypt_avatar`][crate::profile_cipher::ProfileCipher::encrypt_avatar].
    /// This uploads it to the CDN and returns its CDN key.
    /// See [`AccountManager`][struct@crate::AccountManager] for a convenience method.
    ///
    /// Java equivalent: `writeProfile`
    pub async fn write_profile(
        &mut self,
        version: &ProfileKeyVersion,
        name: &[u8],
        about: &[u8],
        emoji: &[u8],
        commitment: &ProfileKeyCommitment,
        avatar: AvatarWrite<Vec<u8>>,
    ) -> Result<Option<String>, ServiceError> {
        // Bincode is transparent and will return a hex-encoded string.
        let version = bincode::serialize(version)?;
        let version = std::str::from_utf8(&version)
            .expect("profile_key_version is hex encoded string");
        let commitment = bincode::serialize(commitment)?;

        let command = SignalServiceProfileWrite {
            version,
            name,
            about,
            about_emoji: emoji,
            avatar: !matches!(avatar, AvatarWrite::NoAvatar),
            same_avatar: matches!(avatar, AvatarWrite::RetainAvatar),
            commitment: &commitment,
        };

        let response = self
            .http_request(Method::PUT, "/v1/profile")?
            .send_json(&command)
            .await?
            .service_error_for_status()
            .await?;

        let AvatarWrite::NewAvatar(encrypted_avatar) = avatar else {
            // The server answers with an empty body when there's nothing to upload.
            return Ok(None);
        };

        // For a new avatar the server answers with a signed S3 form to upload it with.
        let upload_attributes: AttachmentV2UploadAttributes =
            response.json().await?;
        let key = upload_attributes.key.clone();
        self.unidentified_push_service
            .upload_to_cdn0(
                "/",
                upload_attributes,
                "avatar".into(),
                std::io::Cursor::new(encrypted_avatar),
            )
            .await?;

        Ok(Some(key))
    }
}

impl SignalWebSocket<websocket::Unidentified> {
    pub async fn retrieve_profile_avatar(
        &mut self,
        path: &str,
    ) -> Result<impl futures::io::AsyncRead + Send + Unpin, ServiceError> {
        Ok(self
            .unidentified_push_service
            .get_from_cdn(0, path)
            .await?
            .stream)
    }

    pub async fn retrieve_groups_v2_profile_avatar(
        &mut self,
        path: &str,
    ) -> Result<impl futures::io::AsyncRead + Send + Unpin, ServiceError> {
        Ok(self
            .unidentified_push_service
            .get_from_cdn(0, path)
            .await?
            .stream)
    }
}

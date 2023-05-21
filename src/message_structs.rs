use std::collections::HashMap;
use std::error::Error;
use log::debug;
use millegrilles_common_rust::chiffrage_cle::{CommandeSauvegarderCle, InformationCle, MetaInformationCle, ReponseDechiffrageCles};

use millegrilles_common_rust::chrono;
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::chrono::serde::ts_seconds_option;
use millegrilles_common_rust::common_messages::DataChiffre;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::{Map, Value};
use millegrilles_common_rust::bson::serde_helpers::deserialize_chrono_datetime_from_bson_datetime;
use millegrilles_common_rust::messages_generiques::FicheMillegrilleApplication;
use millegrilles_common_rust::multibase::{Base, encode};
use web_push::WebPushMessage;
use crate::constantes::*;

#[derive(Clone, Debug, Serialize)]
pub struct RequeteTopologieResolveIdmg {
    pub dns: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReponseTopologieResolveIdmg {
    pub dns: Option<HashMap<String, Option<String>>>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocMappingIdmg {
    pub dns: Option<Vec<String>>,
    pub push_count: Option<u32>,
    #[serde(default, with = "ts_seconds_option")]
    pub next_push_time: Option<DateTime<Utc>>,
    pub last_result_code: Option<u32>,
    pub attachments_restants: Option<Vec<String>>,
    pub attachments_completes: Option<Vec<String>>,
    pub attachments_en_cours: Option<HashMap<String, AttachmentEnCours>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttachmentEnCours {
    #[serde(default, with = "ts_seconds_option")]
    pub last_update: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DocOutgointProcessing {
    pub transaction_id: String,
    pub message_id: String,
    pub destinataires: Option<Vec<DocDestinataire>>,
    pub user_id: Option<String>,
    pub dns_unresolved: Option<Vec<String>>,
    pub idmgs_unprocessed: Option<Vec<String>>,
    pub idmgs_attachments_unprocessed: Option<Vec<String>>,
    pub idmgs_mapping: Option<HashMap<String, DocMappingIdmg>>,
    pub attachments: Option<Vec<String>>,
    pub dns_failure: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DocDestinataire {
    pub destinataire: String,
    pub user: Option<String>,
    pub dns: Option<String>,
    pub processed: Option<bool>,
    pub result: Option<i32>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AdresseMessagerie {
    pub destinataire: String,
    pub user: String,
    pub dns: Option<String>,
}

impl AdresseMessagerie {

    pub fn new(destinataire: &str) -> Result<Self, String> {
        let mut dest_split = destinataire.split(CONST_ADRESSE_SEPARATEUR_HOST);

        let user: &str = match dest_split.next() {
            Some(mut u) => {
                u = u.trim_start_matches("@");
                Ok(u)
            },
            None => Err(format!("AdresseMessagerie invalide : {}", destinataire))
        }?;

        let hostname: &str = match dest_split.next() {
            Some(d) => Ok(d),
            None => Err(format!("AdresseMessagerie invalide, hostname manquant : {}", destinataire))
        }?;

        Ok(AdresseMessagerie {
            destinataire: destinataire.to_owned(),
            user: user.to_owned(),
            dns: Some(hostname.to_owned()),
        })
    }

}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandePoster {
    pub message: MessageMilleGrille,
    pub destinataires: Vec<String>,
    pub fuuids: Option<Vec<String>>,
}

impl CommandePoster {

    /// Retourne la liste combinee de to et bcc.
    pub fn get_destinataires(&self) -> Vec<String> {
        self.destinataires.clone()
    }

}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocumentOutgoing {
    pub message: MessageMilleGrille,
    pub destinataires: HashMap<String, Option<i64>>,
    pub fuuids: Option<Vec<String>>,
    pub user_id: String,
    pub supprime: bool,
    pub transfert_complete: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocumentMessage {
    pub message_chiffre: String,
    pub attachments: Option<Vec<String>>,
    pub fingerprint_certificat: String,
    pub hachage_bytes: Option<String>,
    pub ref_hachage_bytes: Option<String>,

    // #[serde(rename = "en-tete", skip_serializing)]
    // pub entete: Option<Entete>
}

impl DocumentMessage {
    pub fn get_ref_cle(&'_ self) -> Result<&'_ str, String> {
        match self.ref_hachage_bytes.as_ref() {
            Some(r) => Ok(r.as_str()),
            None => {
                match self.hachage_bytes.as_ref() {
                    Some(h) => Ok(h.as_str()),
                    None => Err(format!("DocumentMessage.get_ref_cle (ref_)hachage_bytes manquant"))?
                }
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionRecevoir {
    pub message: DocumentMessage,
    pub destinataires: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DestinataireInfo {
    pub adresse: Option<String>,
    pub user_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeRecevoirPost {
    pub message: MessageMilleGrille,
    pub destinataires: Vec<String>,
    pub fuuids: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocumentRecevoirPost {
    pub message: MessageMilleGrille,
    pub destinataires_user_id: Vec<DestinataireInfo>,
    pub fuuids: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeRecevoirPostExterne {
    pub cles: HashMap<String, String>,
    pub message: MessageMilleGrille,
    pub transfert: MessageMilleGrille,
}

// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct CommandePostmasterPoster {
//     pub message: Map<String, Value>,
//     pub destinations: Vec<IdmgMappingDestinataires>,
//     pub cle_info: MetaInformationCle,
//     pub certificat_message: Vec<String>,
//     pub certificat_millegrille: String,
// }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseUseridParNomUsager {
    pub usagers: HashMap<String, Option<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequeteGetMessages {
    pub limit: Option<i64>,
    pub skip: Option<u64>,
    pub message_ids: Option<Vec<String>>,
    // pub uuid_transactions: Option<Vec<String>>,
    pub messages_envoyes: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequeteGetReferenceMessages {
    pub skip: Option<u64>,
    pub limit: Option<i64>,
    pub date_maximum: Option<DateEpochSeconds>,
    // pub date_minimum: Option<DateEpochSeconds>,
    pub supprime: Option<bool>,
    pub inclure_supprime: Option<bool>,
    pub messages_envoyes: Option<bool>,
}

// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct MessageIncoming {
//     pub uuid_transaction: String,
//     pub lu: Option<bool>,
//     pub supprime: bool,
//     pub date_reception: Option<DateEpochSeconds>,
//     pub date_envoi: Option<DateEpochSeconds>,
//     pub message_chiffre: String,
//     pub hachage_bytes: Option<String>,
//     pub ref_hachage_bytes: Option<String>,
//     pub header: Option<String>,
//     pub format: Option<String>,
//     pub expiration: Option<i64>,
//     pub niveau: Option<String>,
//     pub certificat_message: Option<Vec<String>>,
//     pub certificat_millegrille: Option<String>,
//     pub attachments: Option<HashMap<String, bool>>,
//     pub attachments_traites: Option<bool>,
// }

// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct AttachedFileDecryption {
//     pub format: String,
//     pub key: Option<String>,
//     pub header: Option<String>,
// }
//
// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct AttachedImage {
//     pub data: Option<String>,
//     pub mimetype: Option<String>,
//     pub width: Option<i64>,
//     pub height: Option<i64>,
//     pub file: Option<String>,
//     pub size: Option<i64>,
//     pub decryption: Option<AttachedFileDecryption>
// }
//
// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct AttachedVideo {
//     pub mimetype: Option<String>,
//     pub width: Option<i64>,
//     pub height: Option<i64>,
//     pub file: Option<String>,
//     pub size: Option<i64>,
//     pub codec: Option<String>,
//     pub bitrate: Option<i64>,
//     pub quality: Option<i64>,
//     pub decryption: Option<AttachedFileDecryption>
// }
//
// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct AttachedMedia {
//     pub animated: Option<bool>,
//     pub duration: Option<i64>,
//     pub height: Option<i64>,
//     pub width: Option<i64>,
//     pub video_codec: Option<String>,
//     pub images: Option<Vec<AttachedImage>>,
//     pub videos: Option<Vec<AttachedVideo>>,
//     pub decryption: Option<AttachedFileDecryption>,
// }
//
// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct AttachedFile {
//     pub name: String,
//     pub date: DateEpochSeconds,
//     pub digest: String,
//     pub size: Option<i64>,
//     pub encrypted_size: Option<i64>,
//     pub file: String,
//     pub mimetype: String,
//     pub media: Option<AttachedMedia>
// }
//
// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct MessageIncoming {
//     pub from: String,
//     pub subject: Option<String>,
//     pub version: i64,
//     pub format: String,
//     pub content: String,
//     pub to: Option<Vec<String>>,
//     pub reply_to: Option<String>,
//     pub cc: Option<Vec<String>>,
//     pub thread: Option<String>,
//     pub files: Option<Vec<AttachedFile>>,
// }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageIncoming {
    pub message: MessageMilleGrille,
    pub fuuids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocumentIncoming {
    pub message: MessageMilleGrille,
    pub user_id: String,
    pub supprime: bool,
    pub lu: bool,
    pub date_reception: DateEpochSeconds,
    pub date_ouverture: Option<DateEpochSeconds>,
    pub fichiers: Option<HashMap<String, bool>>,
    pub fichiers_completes: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageIncomingClient {
    pub message: MessageMilleGrille,
    pub user_id: String,
    pub supprime: bool,
    pub lu: bool,
    pub date_reception: DateEpochSeconds,
    pub date_ouverture: Option<DateEpochSeconds>,
    pub fichiers: Option<HashMap<String, bool>>,
    pub fichiers_completes: bool,
    #[serde(rename="certificat_message")]
    pub certificat: Option<Vec<String>>,
    #[serde(rename="millegrille_message")]
    pub millegrille: Option<String>,
}

impl From<DocumentIncoming> for MessageIncomingClient {
    fn from(value: DocumentIncoming) -> Self {
        Self {
            message: value.message,
            user_id: value.user_id,
            supprime: value.supprime,
            lu: value.lu,
            date_reception: value.date_reception,
            date_ouverture: value.date_ouverture,
            fichiers: value.fichiers,
            fichiers_completes: value.fichiers_completes,
            certificat: None,
            millegrille: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageIncomingReferenceSub {
    pub id: String,
    pub estampille: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageIncomingReference {
    // pub message_id: String,
    pub message: MessageIncomingReferenceSub,
    pub lu: Option<bool>,
    pub supprime: bool,
    pub date_reception: Option<DateEpochSeconds>,
    pub date_envoi: Option<DateEpochSeconds>,
    pub fichiers_completes: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageIncomingAttachments {
    pub message_id: String,
    pub attachments: Option<HashMap<String, bool>>,
    pub attachments_traites: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageOutgoing {
    pub message_id: String,
    pub supprime: bool,
    pub date_envoi: DateEpochSeconds,
    pub message_chiffre: String,
    pub hachage_bytes: String,
    pub attachments: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParametresGetPermissionMessages {
    pub message_ids: Vec<String>,
    pub messages_envoyes: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageIncomingProjectionPermission {
    pub message_ids: String,
    pub hachage_bytes: Option<String>,
    pub ref_hachage_bytes: Option<String>,
    pub attachments: Option<HashMap<String, bool>>,
}

impl MessageIncomingProjectionPermission {
    pub fn get_ref_cle(&'_ self) -> Result<&'_ str, String> {
        match self.ref_hachage_bytes.as_ref() {
            Some(r) => Ok(r.as_str()),
            None => {
                match self.hachage_bytes.as_ref() {
                    Some(h) => Ok(h.as_str()),
                    None => Err(format!("MessageIncomingProjectionPermission.get_ref_cle (ref_)hachage_bytes manquant"))?
                }
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageOutgoingProjectionPermission {
    pub message_id: String,
    pub hachage_bytes: String,
    pub attachments: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParametresGetProfil {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeInitialiserProfil {
    pub adresse: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionInitialiserProfil {
    pub user_id: String,
    pub adresse: String,
    pub cle_ref_hachage_bytes: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProfilReponse {
    pub adresses: Vec<String>,
    pub cle_ref_hachage_bytes: String,
    pub cles: Option<ReponseDechiffrageCles>,
    pub email_actif: Option<bool>,
    pub email_chiffre: Option<DataChiffre>,
    pub notifications_actives: Option<bool>,
    pub webpush_subscriptions: Option<HashMap<String, TransactionSauvegarderSubscriptionWebpush>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParametresGetContacts {
    pub limit: Option<i64>,
    pub skip: Option<u64>,
    pub uuid_contacts: Option<Vec<String>>,
    pub sort_key: Option<SortKey>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contact {
    pub uuid_contact: Option<String>,
    pub data_chiffre: String,
    pub date_modification: Option<DateEpochSeconds>,
    pub format: String,
    pub ref_hachage_bytes: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReferenceContact {
    // pub nom: String,
    pub uuid_contact: Option<String>,
    pub date_modification: Option<DateEpochSeconds>,
    pub supprime: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdresseUserId {
    pub idmg: String,
    #[serde(rename = "userId")]
    pub user_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeLu {
    pub message_id: String,
    pub lu: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionTransfertComplete {
    pub message_id: String,
    pub message_complete: Option<bool>,
    pub attachments_completes: Option<bool>,
    pub destinataires: Option<HashMap<String, i32>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSupprimerMessage {
    pub message_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSupprimerContacts {
    pub uuid_contacts: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdmgMappingDestinataires {
    pub idmg: String,
    pub mapping: DocMappingIdmg,
    pub destinataires: Vec<String>,
    pub fiche: FicheMillegrilleApplication,
    pub cles: HashMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseFichesApplications {
    pub fiches: Vec<FicheMillegrilleApplication>
}

// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct FicheMillegrilleApplication {
//     pub idmg: String,
//     // pub adresses: Vec<String>,
//     pub applications: Vec<FicheApplication>,
//     pub ca: Option<String>,
//     pub chiffrage: Option<Vec<Vec<String>>>,
// }
//
// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct FicheApplication {
//     pub application: String,
//     pub url: String,
//     pub version: Option<String>,
// }

// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct CommandeConfirmerTransmission {
//     pub code: i32,
//     pub idmg: String,
//     pub message_id: String,
//     pub destinataires: Option<Vec<ConfirmerDestinataire>>,
// }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfirmerDestinataire {
    pub code: i32,
    pub destinataire: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandePousserAttachments {
    pub message_id: String,
    pub idmg_destination: String,
}

pub type CommandeProchainAttachment = CommandePousserAttachments;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseProchainAttachment {
    pub fuuid: Option<String>,
    pub ok: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeUploadAttachment {
    pub message_id: String,
    pub idmg: String,
    pub fuuid: String,
    pub code: u32,
    pub http_status: Option<u16>,
    pub retry_after: Option<u32>,
    pub complete: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParametresRequeteAttachmentRequis {
    pub fuuids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseRequeteAttachmentRequis {
    pub fuuids: HashMap<String, bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParametresRequeteUsagerAccesAttachments {
    pub user_id: Option<String>,
    pub fuuids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SortKey {
    pub colonne: String,
    pub ordre: Option<i32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeVerifierExistanceFuuidsMessage {
    pub message_id: String,
    pub fuuids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseVerifierExistanceFuuidsMessage {
    pub fuuids: HashMap<String, bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvenementFichiersConsigne {
    pub hachage_bytes: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageIncomingProjectionAttachments {
    pub user_id: String,
    pub message_id: String,
    pub attachments: Option<HashMap<String, bool>>,
    pub attachments_recus: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvenementConfirmerEtatFuuids {
    pub fuuids: Vec<String>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RowEtatFuuid {
    pub attachments: HashMap<String, bool>,
    pub supprime: bool,
    pub attachments_traites: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequeteConfirmerEtatFuuids {
    pub fuuids: Vec<String>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseConfirmerEtatFuuids {
    pub fuuids: Vec<ConfirmationEtatFuuid>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfirmationEtatFuuid {
    pub fuuid: String,
    pub supprime: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseRecevoirMessages {
    pub ok: Option<bool>,
    pub usagers: Option<HashMap<String, i32>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfirmerMessageComplete {
    pub user_id: String,
    pub message_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfirmerTransmissionMessageMillegrille {
    pub message_id: String,
    pub user_id: String,
    pub idmg: String,
    pub destinataires: Option<Vec<ConfirmerDestinataire>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigurationNotificationsSmtp {
    pub actif: bool,
    pub hostname: String,
    pub port: Option<i64>,
    pub username: String,
    pub replyto: Option<String>,
    pub chiffre: DataChiffre,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigurationNotificationsWebpush {
    pub actif: bool,
    pub icon: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClesConfigurationNotifications {
    pub smtp: Option<CommandeSauvegarderCle>,
    pub webpush: Option<CommandeSauvegarderCle>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionConserverConfigurationNotifications {
    pub email_from: Option<String>,
    pub intervalle_min: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smtp: Option<ConfigurationNotificationsSmtp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webpush: Option<ConfigurationNotificationsWebpush>,
    #[serde(skip_serializing, rename(deserialize="_cles"))]
    pub cles: Option<ClesConfigurationNotifications>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionCleWebpush {
    pub data_chiffre: DataChiffre,
    pub cle_publique_pem: String,
    pub cle_publique_urlsafe: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSauvegarderUsagerConfigNotifications {
    pub email_actif: Option<bool>,
    pub email_chiffre: Option<DataChiffre>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSauvegarderSubscriptionWebpush {
    pub endpoint: String,
    pub expiration_time: Option<i64>,
    pub keys_auth: String,
    pub keys_p256dh: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProfilUsagerNotifications {
    pub cle_ref_hachage_bytes: String,
    pub email_actif: Option<bool>,
    pub email_adresse: Option<String>,
    pub webpush_endpoints: Option<HashMap<String, TransactionSauvegarderSubscriptionWebpush>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UsagerNotificationsOutgoing {
    pub user_id: String,
    #[serde(deserialize_with="deserialize_chrono_datetime_from_bson_datetime")]
    pub derniere_notification: DateTime<Utc>,
    #[serde(deserialize_with="deserialize_chrono_datetime_from_bson_datetime")]
    pub expiration_lock_notifications: DateTime<Utc>,
    pub message_id_notifications: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseConfigurationNotifications {
    pub email_from: Option<String>,
    pub intervalle_min: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smtp: Option<ConfigurationNotificationsSmtp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webpush: Option<ConfigurationNotificationsWebpush>,
    pub webpush_public_key: Option<String>,
    pub cles: Option<HashMap<String, InformationCle>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProfilUsagerDechiffre {
    pub email_adresse: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PostmasterWebPushPayload {
    pub content: String,
    pub crypto_headers: HashMap<String, String>,
    pub content_encoding: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PostmasterWebPushMessage {
    pub endpoint: String,
    pub ttl: u32,
    pub payload: Option<PostmasterWebPushPayload>,
}

impl TryFrom<WebPushMessage> for PostmasterWebPushMessage {
    type Error = Box<dyn Error>;

    fn try_from(value: WebPushMessage) -> Result<Self, Self::Error> {
        let payload = match value.payload {
            Some(inner) => {
                let content: String = encode(Base::Base64, inner.content);

                let mut crypto_headers = HashMap::new();
                for (k, v) in inner.crypto_headers.into_iter() {
                    crypto_headers.insert(k.to_string(), v);
                }

                Some(PostmasterWebPushPayload {
                    content,
                    crypto_headers,
                    content_encoding: inner.content_encoding.to_string(),
                })
            },
            None => None
        };

        Ok(Self {
            endpoint: value.endpoint.to_string(),
            ttl: value.ttl,
            payload,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotificationOutgoingPostmaster {
    pub user_id: String,
    pub email: Option<EmailNotification>,
    pub webpush: Option<Vec<PostmasterWebPushMessage>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebpushConfigurationClePrivee {
    pub cle_privee_pem: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmailNotification {
    pub address: String,
    pub title: String,
    pub body: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocumentNotification {
    pub message_chiffre: String,
    pub attachments: Option<Vec<String>>,
    pub niveau: String,

    // Information de dechiffrage
    pub format: String,
    pub ref_hachage_bytes: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeRecevoir {
    pub message: MessageMilleGrille,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub destinataires: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub niveau: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration: Option<i64>,

    // pub message: DocumentNotification,
    // #[serde(rename="_cle", skip_serializing)]
    // pub cle: Option<MessageMilleGrille>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeTransfertPoster {
    pub to: Vec<String>,
    pub files: Option<Vec<String>>,
}
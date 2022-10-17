use std::collections::HashMap;
use log::debug;
use millegrilles_common_rust::chiffrage_cle::{MetaInformationCle, ReponseDechiffrageCles};

use millegrilles_common_rust::chrono;
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::chrono::serde::ts_seconds_option;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, Entete};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::{Map, Value};
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
    pub uuid_transaction: String,
    pub uuid_message: String,
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
    pub message: DocumentMessage,
    pub destinataires: Vec<String>,
}

impl CommandePoster {

    /// Retourne la liste combinee de to et bcc.
    pub fn get_destinataires(&self) -> Vec<String> {
        self.destinataires.clone()
    }

}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocumentMessage {
    pub message_chiffre: String,
    pub attachments: Option<Vec<String>>,
    pub fingerprint_certificat: String,
    pub hachage_bytes: String,

    #[serde(rename = "en-tete", skip_serializing)]
    pub entete: Option<Entete>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionRecevoir {
    pub message: DocumentMessage,
    pub destinataires: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeRecevoirPost {
    pub message: Map<String, Value>,
    pub destinataires: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandePostmasterPoster {
    pub message: Map<String, Value>,
    pub destinations: Vec<IdmgMappingDestinataires>,
    pub cle_info: MetaInformationCle,
    pub certificat_message: Vec<String>,
    pub certificat_millegrille: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseUseridParNomUsager {
    pub usagers: HashMap<String, Option<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequeteGetMessages {
    pub limit: Option<i64>,
    pub skip: Option<u64>,
    // pub uuid_messages: Option<Vec<String>>,
    pub uuid_transactions: Option<Vec<String>>,
    pub messages_envoyes: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequeteGetReferenceMessages {
    pub limit: Option<i64>,
    pub date_minimum: Option<DateEpochSeconds>,
    pub supprime: Option<bool>,
    pub inclure_supprime: Option<bool>,
    pub messages_envoyes: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageIncoming {
    pub uuid_transaction: String,
    pub lu: Option<bool>,
    pub supprime: bool,
    pub date_reception: Option<DateEpochSeconds>,
    pub date_envoi: Option<DateEpochSeconds>,
    pub message_chiffre: String,
    pub hachage_bytes: String,
    pub certificat_message: Option<Vec<String>>,
    pub certificat_millegrille: Option<String>,
    pub attachments: Option<HashMap<String, bool>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageIncomingReference {
    pub uuid_transaction: String,
    pub lu: Option<bool>,
    pub supprime: bool,
    pub date_reception: Option<DateEpochSeconds>,
    pub date_envoi: Option<DateEpochSeconds>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageOutgoing {
    pub uuid_transaction: String,
    pub supprime: bool,
    pub date_envoi: DateEpochSeconds,
    pub message_chiffre: String,
    pub hachage_bytes: String,
    pub attachments: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParametresGetPermissionMessages {
    pub uuid_transaction_messages: Vec<String>,
    pub messages_envoyes: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageIncomingProjectionPermission {
    pub uuid_transaction: String,
    pub hachage_bytes: String,
    pub attachments: Option<HashMap<String, bool>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageOutgoingProjectionPermission {
    pub uuid_transaction: String,
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
    pub uuid_transaction: String,
    pub lu: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionTransfertComplete {
    pub uuid_message: String,
    pub message_complete: Option<bool>,
    pub attachments_completes: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSupprimerMessage {
    pub uuid_transactions: Vec<String>,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FicheMillegrilleApplication {
    pub idmg: String,
    pub adresses: Vec<String>,
    pub application: Vec<FicheApplication>,
    pub ca: Option<String>,
    pub chiffrage: Option<Vec<Vec<String>>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FicheApplication {
    pub application: String,
    pub url: String,
    pub version: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeConfirmerTransmission {
    pub code: i32,
    pub idmg: String,
    pub uuid_message: String,
    pub destinataires: Option<Vec<ConfirmerDestinataire>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfirmerDestinataire {
    pub code: i32,
    pub destinataire: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandePousserAttachments {
    pub uuid_message: String,
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
    pub uuid_message: String,
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
pub struct SortKey {
    pub colonne: String,
    pub ordre: Option<i32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeVerifierExistanceFuuidsMessage {
    pub uuid_message: String,
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
    pub uuid_transaction: String,
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
    pub usagers: HashMap<String, i32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfirmerMessageComplete {
    pub user_id: String,
    pub uuid_message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfirmerTransmissionMessageMillegrille {
    pub uuid_message: String,
    pub user_id: String,
    pub idmg: String,
    pub destinataires: Vec<ConfirmerDestinataire>,
}


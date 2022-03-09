use std::collections::HashMap;
use log::debug;
use millegrilles_common_rust::chiffrage_cle::MetaInformationCle;

use millegrilles_common_rust::chrono;
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::chrono::serde::ts_seconds_option;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, Entete};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::{Map, Value};

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
        let mut dest_split = destinataire.split("/");

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
    pub uuid_messages: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageIncoming {
    pub uuid_transaction: String,
    pub lu: bool,
    pub supprime: bool,
    pub date_reception: DateEpochSeconds,
    pub message_chiffre: String,
    pub hachage_bytes: String,
    pub certificat_message: Vec<String>,
    pub attachments: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParametresGetPermissionMessages {
    pub uuid_transaction_messages: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageIncomingProjectionPermission {
    pub uuid_transaction: String,
    pub hachage_bytes: String,
    pub attachments: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParametresGetProfil {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionInitialiserProfil {
    pub adresse: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParametresGetContacts {
    pub limit: Option<i64>,
    pub skip: Option<u64>,
    pub uuid_contacts: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contact {
    pub adresses: Option<Vec<String>>,
    pub blocked: Option<bool>,
    pub trusted: Option<bool>,
    // #[serde(rename = "userId", skip_serializing_if = "Option::is_none")]
    // pub user_id: Option<String>,
    pub nom: String,
    pub uuid_contact: Option<String>,
    pub verified: Option<HashMap<String, AdresseUserId>>,
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

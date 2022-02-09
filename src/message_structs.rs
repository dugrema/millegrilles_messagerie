use std::collections::HashMap;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::{Map, Value};

#[derive(Clone, Debug, Serialize)]
pub struct RequeteTopologieResolveIdmg {
    pub dns: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReponseTopologieResolveIdmg {
    pub dns: Option<HashMap<String, String>>
}

#[derive(Clone, Debug, Deserialize)]
pub struct DocMappingIdmg {
    pub dns: Option<Vec<String>>,
    pub retry: Option<u32>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DocOutgointProcessing {
    pub uuid_transaction: String,
    pub destinataires: Option<Vec<DocDestinataire>>,
    pub user_id: Option<String>,
    pub dns_unresolved: Option<Vec<String>>,
    pub idmgs_unprocessed: Option<Vec<String>>,
    pub idmgs_mapping: Option<HashMap<String, DocMappingIdmg>>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DocDestinataire {
    pub destinataire: String,
    pub user: Option<String>,
    pub dns: Option<String>,
    pub idmg: Option<String>,
    pub processed: Option<bool>,
    pub result: Option<i32>,
    pub retry: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionPoster {
    pub message_chiffre: String,
    // pub from: String,
    pub to: Vec<String>,
    pub bcc: Option<Vec<String>>,
    // pub reply_to: Option<String>,
    // pub subject: Option<String>,
    // pub content: Option<String>,
    pub attachments: Option<Vec<String>>,
    pub fingerprint_certificat: String,
}

impl TransactionPoster {

    /// Retourne la liste combinee de to et bcc.
    pub fn get_destinataires(&self) -> Vec<String> {
        let mut destinataires = self.to.clone();
        if let Some(bcc) = &self.bcc {
            for dest in bcc {
                destinataires.push(dest.to_owned());
            }
        }

        destinataires
    }

}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionRecevoir {
    pub message: TransactionPoster,
    pub destinataires: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeRecevoirPost {
    pub message: Map<String, Value>,
    pub destinataires: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseUseridParNomUsager {
    pub usagers: HashMap<String, Option<String>>,
}

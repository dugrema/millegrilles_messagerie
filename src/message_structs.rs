use std::collections::HashMap;
use millegrilles_common_rust::serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize)]
pub struct RequeteTopologieResolveIdmg {
    pub dns: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReponseTopologieResolveIdmg {
    pub dns: Option<HashMap<String, String>>
}

#[derive(Clone, Debug, Deserialize)]
pub struct DocOutgointProcessing {
    pub uuid_transaction: String,
    pub destinataires_dns: Option<Vec<DocDestinataire>>,
    pub user_id: Option<String>,
    pub dns_unresolved: Option<Vec<String>>,
    pub idmgs_unprocessed: Option<Vec<String>>,
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

use std::collections::HashMap;
use millegrilles_common_rust::formatteur_messages::DateEpochSeconds;
use millegrilles_common_rust::serde::{Deserialize, Serialize};

pub const DOMAINE_NOM: &str = "Messagerie";
pub const NOM_COLLECTION_TRANSACTIONS: &str = "Messagerie";
pub const NOM_COLLECTION_INCOMING: &str = "Messagerie/incoming";
pub const NOM_COLLECTION_OUTGOING: &str = "Messagerie/outgoing";
pub const NOM_COLLECTION_OUTGOING_PROCESSING: &str = "Messagerie/outgoing_processing";
pub const NOM_COLLECTION_ATTACHMENTS: &str = "Messagerie/attachments";
pub const NOM_COLLECTION_ATTACHMENTS_PROCESSING: &str = "Messagerie/attachments_processing";

pub const DOMAINE_FICHIERS_NOM: &str = "fichiers";

pub const NOM_Q_TRANSACTIONS: &str = "Messagerie/transactions";
pub const NOM_Q_VOLATILS: &str = "Messagerie/volatils";
pub const NOM_Q_TRIGGERS: &str = "Messagerie/triggers";
pub const NOM_Q_MESSAGE_POMPE: &str = "Messagerie/messagePompe";

// pub const REQUETE_ACTIVITE_RECENTE: &str = "activiteRecente";

pub const TRANSACTION_POSTER: &str = "poster";

// pub const COMMANDE_INDEXER: &str = "indexerContenu";

pub const EVENEMENT_POMPE_POSTE: &str = "pompePoste";

pub const CHAMP_FUUID: &str = "fuuid";  // UUID fichier
pub const CHAMP_FUUIDS: &str = "fuuids";
pub const CHAMP_TUUID: &str = "tuuid";  // UUID transaction initiale (fichier ou collection)
pub const CHAMP_TUUIDS: &str = "tuuids";
pub const CHAMP_CUUID: &str = "cuuid";  // UUID collection de tuuids
pub const CHAMP_CUUIDS: &str = "cuuids";  // Liste de cuuids (e.g. appartenance a plusieurs collections)
pub const CHAMP_SUPPRIME: &str = "supprime";
pub const CHAMP_NOM: &str = "nom";
pub const CHAMP_TITRE: &str = "titre";
pub const CHAMP_MIMETYPE: &str = "mimetype";
pub const CHAMP_FUUID_V_COURANTE: &str = "fuuid_v_courante";
pub const CHAMP_FAVORIS: &str = "favoris";
pub const CHAMP_FUUID_MIMETYPES: &str = "fuuidMimetypes";
pub const CHAMP_FLAG_INDEXE: &str = "flag_indexe";
pub const CHAMP_FLAG_MEDIA: &str = "flag_media";
pub const CHAMP_FLAG_MEDIA_TRAITE: &str = "flag_media_traite";
pub const CHAMP_USER_ID: &str = "user_id";

// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct FichierDetail {
//     pub tuuid: String,
//     #[serde(skip_serializing_if="Option::is_none")]
//     pub cuuids: Option<Vec<String>>,
//     pub nom: String,
//     pub titre: Option<HashMap<String, String>>,
//     pub description: Option<HashMap<String, String>>,
//     pub securite: Option<String>,  // Collection seulement
//     pub user_id: Option<String>,
//
//     pub fuuid_v_courante: Option<String>,
//     pub version_courante: Option<DBFichierVersionDetail>,
//     pub favoris: Option<bool>,
//     pub date_creation: Option<DateEpochSeconds>,
//     pub derniere_modification: Option<DateEpochSeconds>,
//     pub supprime: Option<bool>,
// }
//
// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct DBFichierVersionDetail {
//     pub nom: String,
//     pub fuuid: Option<String>,
//     pub tuuid: Option<String>,
//     pub mimetype: String,
//     pub taille: usize,
//     #[serde(rename="dateFichier")]
//     pub date_fichier: DateEpochSeconds,
//     #[serde(skip_serializing_if="Option::is_none")]
//     pub height: Option<u32>,
//     #[serde(skip_serializing_if="Option::is_none")]
//     pub weight: Option<u32>,
//     #[serde(skip_serializing_if="Option::is_none")]
//     pub images: Option<HashMap<String, ImageConversion>>,
//     #[serde(skip_serializing_if="Option::is_none")]
//     pub anime: Option<bool>,
//     #[serde(skip_serializing_if="Option::is_none")]
//     pub video: Option<HashMap<String, TransactionAssocierVideo>>,
// }
//
// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct TransactionAssocierConversions {
//     pub tuuid: String,
//     pub fuuid: String,
//     pub width: Option<u32>,
//     pub height: Option<u32>,
//     pub mimetype: Option<String>,
//     pub images: HashMap<String, ImageConversion>,
//     pub anime: Option<bool>,
// }
//
// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct TransactionAssocierVideo {
//     pub tuuid: String,
//     pub fuuid: String,
//     pub width: Option<u32>,
//     pub height: Option<u32>,
//     pub mimetype: String,
//     pub fuuid_video: String,
//     pub codec: String,
//     pub bitrate: u32,
//     pub taille_fichier: u64,
// }
//
// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct ImageConversion {
//     pub hachage: String,
//     pub width: Option<u32>,
//     pub height: Option<u32>,
//     pub mimetype: Option<String>,
//     pub taille: Option<u64>,
//     pub resolution: Option<u32>,
//     #[serde(skip_serializing_if="Option::is_none")]
//     pub data_chiffre: Option<String>,
// }

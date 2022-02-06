use std::collections::{HashMap, HashSet};
use std::error::Error;

use log::{debug, error, info, warn};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille};
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::middleware::sauvegarder_traiter_transaction;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, MongoDao};
use millegrilles_common_rust::mongodb::Collection;
use millegrilles_common_rust::mongodb::options::{FindOptions, Hint, UpdateOptions};
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::Transaction;
use millegrilles_common_rust::verificateur::VerificateurMessage;

use crate::gestionnaire::GestionnaireMessagerie;
use crate::constantes::*;
use crate::transactions::*;

pub async fn consommer_commande<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage + ValidateurX509
{
    debug!("consommer_commande : {:?}", &m.message);

    let user_id = m.get_user_id();
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);

    if role_prive && user_id.is_some() {
        // Ok, commande usager
    } else {
        match m.verifier_exchanges(vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure)) {
            true => Ok(()),
            false => {
                // Verifier si on a un certificat delegation globale
                match m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
                    true => Ok(()),
                    false => Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id)),
                }
            }
        }?;
    }

    match m.action.as_str() {
        // Commandes standard
        TRANSACTION_POSTER => commande_poster(middleware, m, gestionnaire).await,

        // COMMANDE_INDEXER => commande_reindexer(middleware, m, gestionnaire).await,

        // Commandes inconnues
        _ => Err(format!("core_backup.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, m.action))?,
    }
}

async fn commande_poster<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_poster Consommer commande : {:?}", & m.message);
    let commande: TransactionPoster = m.message.get_msg().map_contenu(None)?;
    debug!("Commande nouvelle versions parsed : {:?}", commande);

    {
        let version_commande = m.message.get_entete().version;
        if version_commande != 1 {
            Err(format!("commandes.commande_poster: Version non supportee {:?}", version_commande))?
        }
    }

    let user_id = m.get_user_id();
    match m.verifier_exchanges(vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure)) {
        true => {
            // Compte systeme
        },
        false => {
            // Autorisation: Action usager avec compte prive ou delegation globale
            let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
            if role_prive && user_id.is_some() {
                // Ok
            } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
                // Ok
            } else {
                Err(format!("commandes.commande_poster: Commande autorisation invalide pour message {:?}", m.correlation_id))?
            }
        }
    }

    // TODO Valider message

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

// #[derive(Clone, Debug, Deserialize)]
// struct CommandeIndexerContenu {
//     reset: Option<bool>,
//     limit: Option<i64>,
// }

// #[derive(Clone, Debug, Serialize)]
// struct ReponseCommandeReindexer {
//     tuuids: Option<Vec<String>>,
// }
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
use crate::message_structs::*;
use crate::pompe_messages::marquer_outgoing_resultat;

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
        COMMANDE_CONFIRMER_TRANSMISSION => commande_confirmer_transmission(middleware, m, gestionnaire).await,

        // Transactions
        TRANSACTION_POSTER => commande_poster(middleware, m, gestionnaire).await,
        TRANSACTION_RECEVOIR => commande_recevoir(middleware, m, gestionnaire).await,
        TRANSACTION_INITIALISER_PROFIL => commande_initialiser_profil(middleware, m, gestionnaire).await,
        TRANSACTION_MAJ_CONTACT => commande_maj_contact(middleware, m, gestionnaire).await,
        TRANSACTION_LU => commande_lu(middleware, m, gestionnaire).await,

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
    let commande: CommandePoster = m.message.get_msg().map_contenu(None)?;
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

async fn commande_recevoir<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commandes.commande_recevoir Consommer commande : {:?}", & m.message);
    let commande: CommandeRecevoirPost = m.message.get_msg().map_contenu(None)?;
    debug!("commandes.commande_recevoir Commande nouvelle versions parsed : {:?}", commande);

    {
        let version_commande = m.message.get_entete().version;
        if version_commande != 1 {
            Err(format!("commandes.commande_recevoir: Version non supportee {:?}", version_commande))?
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
                Err(format!("commandes.commande_recevoir: Commande autorisation invalide pour message {:?}", m.correlation_id))?
            }
        }
    }

    // TODO Valider message

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_initialiser_profil<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commandes.commande_initialiser_profil Consommer commande : {:?}", & m.message);
    let commande: TransactionInitialiserProfil = m.message.get_msg().map_contenu(None)?;
    debug!("commandes.commande_initialiser_profil Commande nouvelle versions parsed : {:?}", commande);

    {
        let version_commande = m.message.get_entete().version;
        if version_commande != 1 {
            Err(format!("commandes.commande_initialiser_profil: Version non supportee {:?}", version_commande))?
        }
    }

    let user_id = match m.get_user_id() {
        Some(u) => u,
        None => return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "userId manquant", "code": 403}), None)?))
    };
    // Autorisation: Action usager avec compte prive ou delegation globale
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    if role_prive {
        // Ok
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("commandes.commande_initialiser_profil: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    }

    let collection = middleware.get_collection(NOM_COLLECTION_PROFILS)?;
    let filtre = doc! {CHAMP_USER_ID: user_id};
    let doc_profil = collection.find_one(filtre, None).await?;
    if doc_profil.is_some() {
        return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "profil existe deja", "code": 400}), None)?))
    }

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_maj_contact<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commandes.commande_maj_contact Consommer commande : {:?}", & m.message);
    let commande: Contact = m.message.get_msg().map_contenu(None)?;
    debug!("commandes.commande_maj_contact Commande nouvelle versions parsed : {:?}", commande);

    {
        let version_commande = m.message.get_entete().version;
        if version_commande != 1 {
            Err(format!("commandes.commande_initialiser_profil: Version non supportee {:?}", version_commande))?
        }
    }

    let user_id = match m.get_user_id() {
        Some(u) => u,
        None => return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "userId manquant", "code": 403}), None)?))
    };
    // Autorisation: Action usager avec compte prive ou delegation globale
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    if role_prive {
        // Ok
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("commandes.commande_initialiser_profil: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    }

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_lu<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commandes.commande_lu Consommer commande : {:?}", & m.message);
    let commande: CommandeLu = m.message.get_msg().map_contenu(None)?;
    debug!("commandes.commande_lu Commande nouvelle versions parsed : {:?}", commande);

    {
        let version_commande = m.message.get_entete().version;
        if version_commande != 1 {
            Err(format!("commandes.commande_initialiser_profil: Version non supportee {:?}", version_commande))?
        }
    }

    let user_id = match m.get_user_id() {
        Some(u) => u,
        None => return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "userId manquant", "code": 403}), None)?))
    };
    // Autorisation: Action usager avec compte prive ou delegation globale
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    if role_prive {
        // Ok
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("commandes.commande_initialiser_profil: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    }

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_confirmer_transmission<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + MongoDao + GenerateurMessages
{
    debug!("commande_confirmer_transmission Consommer commande : {:?}", & m.message);
    let commande: CommandeConfirmerTransmission = m.message.get_msg().map_contenu(None)?;
    debug!("commande_confirmer_transmission Commande parsed : {:?}", commande);

    let uuid_message = commande.uuid_message.as_str();
    let idmg = commande.idmg.as_str();

    let destinataires = match commande.destinataires.as_ref() {
        Some(d) => {
            d.iter().map(|d| d.destinataire.clone()).collect()
        },
        None => Vec::new()
    };

    let result_code = commande.code as u32;
    let processed = match &commande.code {
        200 => true,
        201 => true,
        _ => false
    };

    marquer_outgoing_resultat(middleware, uuid_message, idmg, &destinataires, processed, result_code).await?;

    Ok(None)
}

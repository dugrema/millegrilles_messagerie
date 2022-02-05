use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::convert::{TryFrom, TryInto};
use std::ops::Deref;

use log::{debug, error, warn};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{Bson, doc, Document};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille};
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::middleware::sauvegarder_traiter_transaction;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, filtrer_doc_id, MongoDao};
use millegrilles_common_rust::mongodb::Cursor;
use millegrilles_common_rust::mongodb::options::{FindOptions, Hint, UpdateOptions};
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::Transaction;
use millegrilles_common_rust::verificateur::VerificateurMessage;

use crate::gestionnaire::GestionnaireMessagerie;
use crate::constantes::*;
use crate::transactions::*;

pub async fn consommer_requete<M>(middleware: &M, message: MessageValideAction, gestionnaire: &GestionnaireMessagerie) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + VerificateurMessage
{
    debug!("Consommer requete : {:?}", &message.message);

    let user_id = message.get_user_id();
    let role_prive = message.verifier_roles(vec![RolesCertificats::ComptePrive]);

    if role_prive && user_id.is_some() {
        // Ok, commande usager
    } else if message.verifier_exchanges(vec![Securite::L2Prive, Securite::L3Protege]) {
        // Autorisation : On accepte les requetes de 3.protege ou 4.secure
        // Ok
    } else if message.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("consommer_requete autorisation invalide (pas d'un exchange reconnu)"))?
    }

    match message.domaine.as_str() {
        DOMAINE_NOM => {
            match message.action.as_str() {
                // REQUETE_ACTIVITE_RECENTE => requete_activite_recente(middleware, message, gestionnaire).await,
                _ => {
                    error!("Message requete/action inconnue : '{}'. Message dropped.", message.action);
                    Ok(None)
                },
            }
        },
        _ => {
            error!("Message requete/domaine inconnu : '{}'. Message dropped.", message.domaine);
            Ok(None)
        },
    }
}

// async fn requete_activite_recente<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
//     -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
//     where M: GenerateurMessages + MongoDao + VerificateurMessage,
// {
//     debug!("requete_activite_recente Message : {:?}", & m.message);
//     let requete: RequetePlusRecente = m.message.get_msg().map_contenu(None)?;
//     debug!("requete_activite_recente cle parsed : {:?}", requete);
//
//     let user_id = m.get_user_id();
//     if user_id.is_none() {
//         return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "msg": "Access denied"}), None)?))
//     }
//
//     let limit = match requete.limit {
//         Some(l) => l,
//         None => 100
//     };
//     let skip = match requete.skip {
//         Some(s) => s,
//         None => 0
//     };
//
//     let opts = FindOptions::builder()
//         .hint(Hint::Name(String::from("fichiers_activite_recente")))
//         .sort(doc!{CHAMP_SUPPRIME: -1, CHAMP_MODIFICATION: -1, CHAMP_TUUID: 1})
//         .limit(limit)
//         .skip(skip)
//         .build();
//     let filtre = doc!{CHAMP_SUPPRIME: false, CHAMP_USER_ID: user_id};
//
//     let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
//     let mut curseur = collection.find(filtre, opts).await?;
//     let fichiers_mappes = mapper_fichiers_curseur(curseur).await?;
//
//     let reponse = json!({ "fichiers": fichiers_mappes });
//     Ok(Some(middleware.formatter_reponse(&reponse, None)?))
// }

// async fn mapper_fichiers_curseur(mut curseur: Cursor<Document>) -> Result<Value, Box<dyn Error>> {
//     let mut fichiers_mappes = Vec::new();
//
//     while let Some(fresult) = curseur.next().await {
//         let fcurseur = fresult?;
//         let fichier_db = mapper_fichier_db(fcurseur)?;
//         fichiers_mappes.push(fichier_db);
//     }
//
//     // Convertir fichiers en Value (serde pour reponse json)
//     Ok(serde_json::to_value(fichiers_mappes)?)
// }

// #[derive(Clone, Debug, Serialize, Deserialize)]
// struct RequetePlusRecente {
//     limit: Option<i64>,
//     skip: Option<u64>,
// }

// pub fn mapper_fichier_db(fichier: Document) -> Result<FichierDetail, Box<dyn Error>> {
//     let date_creation = fichier.get_datetime(CHAMP_CREATION)?.clone();
//     let date_modification = fichier.get_datetime(CHAMP_MODIFICATION)?.clone();
//     let mut fichier_mappe: FichierDetail = convertir_bson_deserializable(fichier)?;
//     fichier_mappe.date_creation = Some(DateEpochSeconds::from(date_creation.to_chrono()));
//     fichier_mappe.derniere_modification = Some(DateEpochSeconds::from(date_modification.to_chrono()));
//     debug!("Fichier mappe : {:?}", fichier_mappe);
//     Ok(fichier_mappe)
// }

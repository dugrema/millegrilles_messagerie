use std::collections::HashMap;
use std::error::Error;
use std::convert::TryInto;

use log::{debug, error, warn};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::{bson, bson::{doc, Document}};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille};
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::middleware::sauvegarder_transaction_recue;
use millegrilles_common_rust::mongo_dao::{convertir_to_bson, MongoDao};
use millegrilles_common_rust::mongodb::options::UpdateOptions;
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::transactions::Transaction;
use crate::gestionnaire::GestionnaireMessagerie;

use crate::constantes::*;

pub async fn consommer_transaction<M>(middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("transactions.consommer_transaction Consommer transaction : {:?}", &m.message);

    // Autorisation
    match m.action.as_str() {
        // 4.secure - doivent etre validees par une commande
        // TRANSACTION_NOUVELLE_VERSION |
        // TRANSACTION_DECRIRE_COLLECTION => {
        //     match m.verifier_exchanges(vec![Securite::L4Secure]) {
        //         true => Ok(()),
        //         false => Err(format!("transactions.consommer_transaction: Trigger cedule autorisation invalide (pas 4.secure)"))
        //     }?;
        // },
        // 3.protege ou 4.secure
        // TRANSACTION_ASSOCIER_CONVERSIONS |
        // TRANSACTION_ASSOCIER_VIDEO => {
        //     match m.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure]) {
        //         true => Ok(()),
        //         false => Err(format!("transactions.consommer_transaction: Trigger cedule autorisation invalide (pas 4.secure)")),
        //     }?;
        // },
        _ => Err(format!("transactions.consommer_transaction: Mauvais type d'action pour une transaction : {}", m.action))?,
    }

    sauvegarder_transaction_recue(middleware, m, NOM_COLLECTION_TRANSACTIONS).await?;

    Ok(None)
}

pub async fn aiguillage_transaction<M, T>(gestionnaire: &GestionnaireMessagerie, middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao,
        T: Transaction
{
    match transaction.get_action() {
        // TRANSACTION_NOUVELLE_VERSION => transaction_nouvelle_version(gestionnaire, middleware, transaction).await,
        _ => Err(format!("core_backup.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.get_uuid_transaction(), transaction.get_action())),
    }
}

// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct TransactionNouvelleVersion {
//     fuuid: String,
//     cuuid: Option<String>,
//     tuuid: Option<String>,  // uuid de la premiere commande/transaction comme collateur de versions
//     nom: String,
//     mimetype: String,
//     taille: u64,
//     #[serde(rename="dateFichier")]
//     date_fichier: DateEpochSeconds,
// }

// async fn transaction_nouvelle_version<M, T>(gestionnaire: &GestionnaireMessagerie, middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
//     where
//         M: GenerateurMessages + MongoDao,
//         T: Transaction
// {
//     debug!("transaction_nouvelle_version Consommer transaction : {:?}", &transaction);
//     let transaction_fichier: TransactionNouvelleVersion = match transaction.clone().convertir::<TransactionNouvelleVersion>() {
//         Ok(t) => t,
//         Err(e) => Err(format!("grosfichiers.transaction_nouvelle_version Erreur conversion transaction : {:?}", e))?
//     };
//
//     // Determiner tuuid - si non fourni, c'est l'uuid-transaction (implique un nouveau fichier)
//     let tuuid = match &transaction_fichier.tuuid {
//         Some(t) => t.clone(),
//         None => String::from(transaction.get_uuid_transaction())
//     };
//
//     // Conserver champs transaction uniquement (filtrer champs meta)
//     let mut doc_bson_transaction = match convertir_to_bson(&transaction_fichier) {
//         Ok(d) => d,
//         Err(e) => Err(format!("grosfichiers.transaction_nouvelle_version Erreur conversion transaction en bson : {:?}", e))?
//     };
//
//     let fuuid = transaction_fichier.fuuid;
//     let cuuid = transaction_fichier.cuuid;
//     let nom_fichier = transaction_fichier.nom;
//     let mimetype = transaction_fichier.mimetype;
//
//     let user_id = match transaction.get_enveloppe_certificat() {
//         Some(e) => {
//             e.get_user_id()?.to_owned()
//         },
//         None => None
//     };
//
//     doc_bson_transaction.insert(CHAMP_FUUID_MIMETYPES, doc! {&fuuid: &mimetype});
//
//     // Retirer champ CUUID, pas utile dans l'information de version
//     doc_bson_transaction.remove(CHAMP_CUUID);
//
//     let mut flag_media = false;
//
//     // Inserer document de version
//     {
//         let collection = middleware.get_collection(NOM_COLLECTION_VERSIONS)?;
//         let mut doc_version = doc_bson_transaction.clone();
//         doc_version.insert(CHAMP_TUUID, &tuuid);
//         doc_version.insert(CHAMP_FUUIDS, vec![&fuuid]);
//
//         // Information optionnelle pour accelerer indexation/traitement media
//         if mimetype.starts_with("image") {
//             flag_media = true;
//             doc_version.insert(CHAMP_FLAG_MEDIA, "image");
//             doc_version.insert(CHAMP_FLAG_MEDIA_TRAITE, false);
//         } else if mimetype.starts_with("video") {
//             flag_media = true;
//             doc_version.insert(CHAMP_FLAG_MEDIA, "video");
//             doc_version.insert(CHAMP_FLAG_MEDIA_TRAITE, false);
//         } else if mimetype =="application/pdf" {
//             flag_media = true;
//             doc_version.insert(CHAMP_FLAG_MEDIA, "poster");
//             doc_version.insert(CHAMP_FLAG_MEDIA_TRAITE, false);
//         }
//         doc_version.insert(CHAMP_FLAG_INDEXE, false);
//
//         match collection.insert_one(doc_version, None).await {
//             Ok(_) => (),
//             Err(e) => Err(format!("grosfichiers.transaction_nouvelle_version Erreur insertion nouvelle version {} : {:?}", fuuid, e))?
//         }
//     }
//
//     // Retirer champs cles - ils sont inutiles dans la version
//     doc_bson_transaction.remove(CHAMP_TUUID);
//     doc_bson_transaction.remove(CHAMP_FUUID);
//
//     let filtre = doc! {CHAMP_TUUID: &tuuid};
//     let mut add_to_set = doc!{"fuuids": &fuuid};
//     // Ajouter collection au besoin
//     if let Some(c) = cuuid {
//         add_to_set.insert("cuuids", c);
//     }
//
//     let ops = doc! {
//         "$set": {
//             "version_courante": doc_bson_transaction,
//             CHAMP_FUUID_V_COURANTE: &fuuid,
//             CHAMP_MIMETYPE: &mimetype,
//             CHAMP_SUPPRIME: false,
//         },
//         "$addToSet": add_to_set,
//         "$setOnInsert": {
//             "nom": &nom_fichier,
//             "tuuid": &tuuid,
//             CHAMP_CREATION: Utc::now(),
//             CHAMP_USER_ID: &user_id,
//         },
//         "$currentDate": {CHAMP_MODIFICATION: true}
//     };
//     let opts = UpdateOptions::builder().upsert(true).build();
//     let collection = middleware.get_collection(NOM_COLLECTION_FICHIERS_REP)?;
//     debug!("nouveau fichier update ops : {:?}", ops);
//     let resultat = match collection.update_one(filtre, ops, opts).await {
//         Ok(r) => r,
//         Err(e) => Err(format!("grosfichiers.transaction_cle Erreur update_one sur transcation : {:?}", e))?
//     };
//     debug!("nouveau fichier Resultat transaction update : {:?}", resultat);
//
//     if flag_media == true {
//         debug!("Emettre une commande de conversion pour media {}", fuuid);
//         match emettre_commande_media(middleware, &tuuid, &fuuid, &mimetype).await {
//             Ok(()) => (),
//             Err(e) => error!("transactions.transaction_nouvelle_version Erreur emission commande poster media {} : {:?}", fuuid, e)
//         }
//     }
//
//     debug!("Emettre une commande d'indexation pour {}", fuuid);
//     match emettre_commande_indexation(gestionnaire, middleware, &tuuid, &fuuid).await {
//         Ok(()) => (),
//         Err(e) => error!("transactions.transaction_nouvelle_version Erreur emission commande poster media {} : {:?}", fuuid, e)
//     }
//
//     // Emettre fichier pour que tous les clients recoivent la mise a jour
//     emettre_evenement_maj_fichier(middleware, &tuuid).await?;
//
//     middleware.reponse_ok()
// }

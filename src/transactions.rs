use std::collections::{HashMap, HashSet};
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
        TRANSACTION_POSTER => {
            match m.verifier_exchanges(vec![Securite::L4Secure]) {
                true => Ok(()),
                false => Err(format!("transactions.consommer_transaction: Trigger cedule autorisation invalide (pas 4.secure)"))
            }?;
        },
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
        TRANSACTION_POSTER => transaction_poster(gestionnaire, middleware, transaction).await,
        _ => Err(format!("core_backup.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.get_uuid_transaction(), transaction.get_action())),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionPoster {
    from: String,
    to: Vec<String>,
    cc: Option<Vec<String>>,
    bcc: Option<Vec<String>>,
    reply_to: Option<String>,
    subject: Option<String>,
    content: Option<String>,
    attachments: Option<Vec<String>>,
}

async fn transaction_poster<M, T>(gestionnaire: &GestionnaireMessagerie, middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_poster Consommer transaction : {:?}", &transaction);
    let uuid_transaction = transaction.get_uuid_transaction();
    let user_id = match transaction.get_enveloppe_certificat() {
        Some(e) => e.get_user_id()?.to_owned(),
        None => None
    };

    let transaction_poster: TransactionPoster = match transaction.clone().convertir::<TransactionPoster>() {
        Ok(t) => t,
        Err(e) => Err(format!("messagerie.transaction_poster Erreur conversion transaction : {:?}", e))?
    };

    // Conserver document dans outgoing et flags dans outgoing_processing
    let mut doc_bson_transaction = match convertir_to_bson(&transaction_poster) {
        Ok(d) => d,
        Err(e) => Err(format!("transactions.transaction_poster Erreur conversion transaction en bson : {:?}", e))?
    };

    let mut dns_adresses: HashSet<String> = HashSet::new();
    let mut destinataires = Document::new();
    for dest in &transaction_poster.to {
        let mut dest_split = dest.split("/");
        let mut user: &str = dest_split.next().expect("user");
        if user.starts_with("@") {
            user = user.trim_start_matches("@");
        }
        let dns_addr = dest_split.next().expect("dns_addr");
        dns_adresses.insert(dns_addr.into());
        let flags = doc! {
            "user": user,
            "dns": dns_addr,
            "idmg": None::<&str>,
            "sent": false,
            "retry": 0,
        };
        destinataires.insert(dest.to_owned(), flags);
    }

    let dns_adresses: Vec<String> = dns_adresses.into_iter().collect();
    let doc_processing = doc! {
        TRANSACTION_CHAMP_UUID_TRANSACTION: uuid_transaction,
        "destinataires": destinataires,
        "user_id": user_id,
        "dns": dns_adresses,
    };

    // Inserer document de message dans outgoing
    {
        let collection = middleware.get_collection(NOM_COLLECTION_OUTGOING)?;
        match collection.insert_one(doc_bson_transaction, None).await {
            Ok(_) => (),
            Err(e) => Err(format!("transactions.transaction_poster Erreur insertion vers outgoing {} : {:?}", uuid_transaction, e))?
        }
    }

    // Inserer document de traitement dans outgoint_processing
    {
        let collection = middleware.get_collection(NOM_COLLECTION_OUTGOING_PROCESSING)?;
        match collection.insert_one(doc_processing, None).await {
            Ok(_) => (),
            Err(e) => Err(format!("transactions.transaction_poster Erreur insertion vers outgoing_processing {} : {:?}", uuid_transaction, e))?
        }
    }

    // Emettre requete resolve vers CoreTopologie
    // emettre_evenement_maj_fichier(middleware, &tuuid).await?;

    middleware.reponse_ok()
}

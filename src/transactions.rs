use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::convert::TryInto;

use log::{debug, error, warn};
use millegrilles_common_rust::{chrono, serde_json, serde_json::json};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::{bson, bson::{doc, Document}};
use millegrilles_common_rust::bson::{Array, Bson};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, Entete, MessageMilleGrille, MessageSerialise};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::middleware::{map_msg_to_bson, map_serializable_to_bson, sauvegarder_transaction_recue};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, MongoDao};
use millegrilles_common_rust::mongodb::options::UpdateOptions;
use millegrilles_common_rust::recepteur_messages::{MessageValideAction, TypeMessage};
use millegrilles_common_rust::redis::ToRedisArgs;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::transactions::Transaction;
use millegrilles_common_rust::tokio_stream::StreamExt;

use crate::constantes::*;
use crate::gestionnaire::GestionnaireMessagerie;
use crate::message_structs::*;
use crate::pompe_messages::emettre_evenement_pompe;

pub async fn consommer_transaction<M>(middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("transactions.consommer_transaction Consommer transaction : {:?}", &m.message);

    // Autorisation
    match m.action.as_str() {
        // 4.secure - doivent etre validees par une commande
        TRANSACTION_POSTER |
        TRANSACTION_RECEVOIR => {
            match m.verifier_exchanges(vec![Securite::L4Secure]) {
                true => Ok(()),
                false => Err(format!("transactions.consommer_transaction: Trigger cedule autorisation invalide (pas 4.secure)"))
            }?;
        },
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
        TRANSACTION_RECEVOIR => transaction_recevoir(gestionnaire, middleware, transaction).await,
        _ => Err(format!("core_backup.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.get_uuid_transaction(), transaction.get_action())),
    }
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
    doc_bson_transaction.insert("uuid_transaction", &uuid_transaction);
    doc_bson_transaction.insert("user_id", &user_id);

    let mut dns_adresses: HashSet<String> = HashSet::new();
    let mut destinataires = Array::new();
    for dest in &transaction_poster.to {
        let mut dest_split = dest.split("/");
        let mut user: &str = dest_split.next().expect("user");
        if user.starts_with("@") {
            user = user.trim_start_matches("@");
        }
        let dns_addr = dest_split.next().expect("dns_addr");
        dns_adresses.insert(dns_addr.into());
        let flags = doc! {
            "destinataire": dest,
            "user": user,
            "dns": dns_addr,
            "processed": false,
            "result": None::<&str>,
        };

        destinataires.push(Bson::Document(flags));
    }

    let dns_adresses: Vec<String> = dns_adresses.into_iter().collect();
    let doc_processing = doc! {
        TRANSACTION_CHAMP_UUID_TRANSACTION: uuid_transaction,
        "destinataires": destinataires,
        "user_id": user_id,
        "dns_unresolved": &dns_adresses,
        "idmgs_mapping": doc!{},
        "idmgs_unprocessed": Vec::<String>::new(),
        "created": chrono::Utc::now(),
    };

    // Inserer document de message dans outgoing
    {
        let collection = middleware.get_collection(NOM_COLLECTION_OUTGOING)?;
        match collection.insert_one(doc_bson_transaction, None).await {
            Ok(_) => (),
            Err(e) => Err(format!("transactions.transaction_poster Erreur insertion vers outgoing {} : {:?}", uuid_transaction, e))?
        }
    }

    // Inserer document de traitement dans outgoing_processing
    {
        let collection = middleware.get_collection(NOM_COLLECTION_OUTGOING_PROCESSING)?;
        match collection.insert_one(doc_processing, None).await {
            Ok(_) => (),
            Err(e) => Err(format!("transactions.transaction_poster Erreur insertion vers outgoing_processing {} : {:?}", uuid_transaction, e))?
        }
    }

    // Emettre requete resolve vers CoreTopologie
    // emettre_evenement_maj_fichier(middleware, &tuuid).await?;
    match emettre_requete_resolve(gestionnaire, middleware, uuid_transaction, &dns_adresses).await {
        Ok(()) => (),
        Err(e) => Err(format!("transactions.transaction_poster Erreur requete resolve idmg {:?}", e))?,
    }

    middleware.reponse_ok()
}

async fn emettre_requete_resolve<M>(gestionnaire: &GestionnaireMessagerie, middleware: &M, uuid_transaction: &str, dns: &Vec<String>)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + MongoDao
{
    let correlation_id = format!("outgoing_resolved:{}", uuid_transaction);

    let routage = RoutageMessageAction::builder("CoreTopologie", "resolveIdmg")
        .exchanges(vec!(Securite::L2Prive))
        .build();

    let requete = RequeteTopologieResolveIdmg {
        dns: Some(dns.to_owned()),
    };

    let reponse = middleware.transmettre_requete(routage, &requete).await?;
    debug!("transactions.emettre_requete_resolve Reponse resolve topologie : {:?}", reponse);
    match reponse {
        TypeMessage::Valide(r) => {
            debug!("Reponse resolve idmg : {:?}", r);
            let contenu: ReponseTopologieResolveIdmg = r.message.parsed.map_contenu(None)?;
            debug!("Reponse resolve idmg contenu parsed : {:?}", contenu);
            traiter_outgoing_resolved(gestionnaire, middleware, &contenu).await?;
        },
        _ => Err(format!("Erreur resolve idmg, mauvais type de reponse"))?
    }

    Ok(())
}

async fn traiter_outgoing_resolved<M>(gestionnaire: &GestionnaireMessagerie, middleware: &M, reponse: &ReponseTopologieResolveIdmg)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + MongoDao
{
    debug!("transactions.traiter_outgoing_resolved Reponse a traiter : {:?}", reponse);
    let collection = middleware.get_collection(NOM_COLLECTION_OUTGOING_PROCESSING)?;

    let mut idmgs: HashSet<String> = HashSet::new();

    if let Some(d) = &reponse.dns {
        for (dns, idmg) in d {
            idmgs.insert(idmg.to_owned());

            let filtre = doc! {"dns_unresolved": {"$all": [dns]}};
            let ops = doc! {
                "$set": {
                    format!("idmgs_mapping.{}.retry", idmg): 0,
                },
                "$addToSet": {
                    format!("idmgs_mapping.{}.dns", idmg): dns,
                    "idmgs_unprocessed": idmg,
                },
                "$pull": {"dns_unresolved": dns},
                "$currentDate": {"last_processed": true},
            };
            collection.update_many(filtre, ops, None).await?;
        }
    }

    emettre_evenement_pompe(middleware, Some(idmgs.into_iter().collect())).await?;

    Ok(())
}

async fn transaction_recevoir<M, T>(gestionnaire: &GestionnaireMessagerie, middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao + ValidateurX509,
        T: Transaction
{
    debug!("transaction_recevoir Consommer transaction : {:?}", &transaction);
    let uuid_transaction = transaction.get_uuid_transaction().to_owned();

    let transaction_recevoir: TransactionRecevoir = match transaction.clone().convertir::<TransactionRecevoir>() {
        Ok(t) => t,
        Err(e) => Err(format!("transaction_recevoir Erreur conversion transaction : {:?}", e))?
    };

    // Conserver message pour chaque destinataires locaux
    let message_enveloppe = transaction_recevoir.message;
    let message_chiffre = message_enveloppe.message_chiffre;
    let fingerprint_usager = message_enveloppe.fingerprint_certificat;
    let destinataires = transaction_recevoir.destinataires;
    let attachments = message_enveloppe.attachments;

    // Resolve destinataires nom_usager => user_id
    let reponse_mappee: ReponseUseridParNomUsager = {
        let requete_routage = RoutageMessageAction::builder("CoreMaitreDesComptes", "getUserIdParNomUsager")
            .exchanges(vec![Securite::L4Secure])
            .build();
        let requete = json!({"noms_usagers": &destinataires});
        debug!("transaction_recevoir Requete {:?} pour user names : {:?}", requete_routage, requete);
        let reponse = middleware.transmettre_requete(requete_routage, &requete).await?;
        debug!("transaction_recevoir Reponse mapping users : {:?}", reponse);
        match reponse {
            TypeMessage::Valide(m) => {
                match m.message.parsed.map_contenu(None) {
                    Ok(m) => m,
                    Err(e) => Err(format!("pompe_messages.transaction_recevoir Erreur mapping reponse requete noms usagers : {:?}", e))?
                }
            },
            _ => Err(format!("pompe_messages.transaction_recevoir Erreur mapping reponse requete noms usagers, mauvais type reponse"))?
        }
    };

    let collection = middleware.get_collection(NOM_COLLECTION_INCOMING)?;
    // let message_recu_bson = match map_serializable_to_bson(&message_recu) {
    //     Ok(m) => m,
    //     Err(e) => Err(format!("transactions.transaction_recevoir Erreur insertion message {} : {:?}", uuid_transaction, e))?
    // };
    let certificat_usager = middleware.get_certificat(fingerprint_usager.as_str()).await;
    let certificat_usager_pem: Vec<String> = match certificat_usager {
        Some(c) => {
            let fp_certs = c.get_pem_vec();
            fp_certs.into_iter().map(|c| c.pem).collect()
        },
        None => Err(format!("transactions.transaction_recevoir Erreur insertion message {}, certificat {} introuvable", uuid_transaction, fingerprint_usager))?
    };

    for (nom_usager, user_id) in &reponse_mappee.usagers {
        match user_id {
            Some(u) => {
                // Sauvegarder message pour l'usager
                debug!("transaction_recevoir Sauvegarder message pour usager : {}", u);
                let doc_user_reception = doc! {
                    "user_id": u,
                    "uuid_transaction": &uuid_transaction,
                    "lu": false,
                    "date_reception": chrono::Utc::now(),
                    "certificat_message": &certificat_usager_pem,
                    "message_chiffre": &message_chiffre,
                    "attachments": &attachments,
                };
                if let Err(e) = collection.insert_one(doc_user_reception, None).await {
                    Err(format!("transactions.transaction_recevoir Erreur insertion message {} pour usager {} : {:?}", uuid_transaction, u, e))?
                }
            },
            None => warn!("transaction_recevoir Nom usager local inconnu : {}", nom_usager)
        }
    }

    middleware.reponse_ok()
}

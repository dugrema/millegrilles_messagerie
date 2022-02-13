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
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, FindOptions, ReturnDocument, UpdateOptions};
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
        TRANSACTION_RECEVOIR |
        TRANSACTION_INITIALISER_PROFIL |
        TRANSACTION_MAJ_CONTACT |
        TRANSACTION_LU => {
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
        TRANSACTION_INITIALISER_PROFIL => transaction_initialiser_profil(gestionnaire, middleware, transaction).await,
        TRANSACTION_MAJ_CONTACT => transaction_maj_contact(gestionnaire, middleware, transaction).await,
        TRANSACTION_LU => transaction_lu(gestionnaire, middleware, transaction).await,
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
    let liste_destinataires = transaction_poster.get_destinataires();
    for dest in liste_destinataires.into_iter() {
        let mut dest_split = dest.split("/");
        let mut user: &str = match dest_split.next() {
            Some(u) => u,
            None => {
                debug!("dest invalide, on l'ignore : {}", dest);
                continue
            }
        };
        let dns_addr = match dest_split.next() {
            Some(d) => d,
            None => {
                debug!("dest invalide, serveur manquant, on l'ignore : {}", dest);
                continue
            }
        };

        if user.starts_with("@") {
            user = user.trim_start_matches("@");
        }
        dns_adresses.insert(dns_addr.into());
        let flags = doc! {
            "destinataire": &dest,
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
    // {
    //     let collection = middleware.get_collection(NOM_COLLECTION_OUTGOING)?;
    //     match collection.insert_one(doc_bson_transaction, None).await {
    //         Ok(_) => (),
    //         Err(e) => Err(format!("transactions.transaction_poster Erreur insertion vers outgoing {} : {:?}", uuid_transaction, e))?
    //     }
    // }

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
    let hachage_bytes = message_enveloppe.hachage_bytes;
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
        let now: Bson = DateEpochSeconds::now().into();
        match user_id {
            Some(u) => {
                // Sauvegarder message pour l'usager
                debug!("transaction_recevoir Sauvegarder message pour usager : {}", u);
                let doc_user_reception = doc! {
                    "user_id": u,
                    "uuid_transaction": &uuid_transaction,
                    "lu": false,
                    CHAMP_SUPPRIME: false,
                    "date_reception": now,
                    "date_ouverture": None::<&str>,
                    "certificat_message": &certificat_usager_pem,
                    "message_chiffre": &message_chiffre,
                    "hachage_bytes": &hachage_bytes,
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

async fn transaction_initialiser_profil<M, T>(gestionnaire: &GestionnaireMessagerie, middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao + ValidateurX509,
        T: Transaction
{
    debug!("transaction_initialiser_profil Consommer transaction : {:?}", &transaction);
    let uuid_transaction = transaction.get_uuid_transaction().to_owned();

    let transaction_initialiser_profil: TransactionInitialiserProfil = match transaction.clone().convertir::<TransactionInitialiserProfil>() {
        Ok(t) => t,
        Err(e) => Err(format!("transactions.transaction_initialiser_profil Erreur conversion transaction : {:?}", e))?
    };
    let adresse = transaction_initialiser_profil.adresse;

    let certificat = match transaction.get_enveloppe_certificat() {
        Some(c) => c,
        None => Err(format!("transactions.transaction_initialiser_profil Certificat invalide/non charge"))?
    };
    let user_id = match certificat.get_user_id()? {
        Some(u) => u,
        None => Err(format!("transactions.transaction_initialiser_profil user_id manquant du certificat"))?
    };

    let collection = middleware.get_collection(NOM_COLLECTION_PROFILS)?;
    let filtre = doc! {CHAMP_USER_ID: user_id};
    let options = FindOneAndUpdateOptions::builder()
        .upsert(true)
        .return_document(ReturnDocument::After)
        .build();
    let ops = doc! {
        "$set": {"adresses": [adresse]},
        "$currentDate": {CHAMP_CREATION: true, CHAMP_MODIFICATION: true},
    };

    let mut doc_profil = match collection.find_one_and_update(filtre, ops, options).await {
        Ok(d) => match d {
            Some(d) => d,
            None => Err(format!("transactions.transaction_initialiser_profil user_id Erreur de creation du profil, document vide"))?
        },
        Err(e) => Err(format!("transactions.transaction_initialiser_profil user_id Erreur de creation du profil : {:?}", e))?
    };

    doc_profil.remove("_id");
    doc_profil.remove(CHAMP_CREATION);
    doc_profil.remove(CHAMP_MODIFICATION);

    let reponse = match middleware.formatter_reponse(doc_profil, None) {
        Ok(r) => r,
        Err(e) => Err(format!("transactions.transaction_initialiser_profil user_id Erreur de creation du profil : {:?}", e))?
    };

    Ok(Some(reponse))
}

async fn transaction_maj_contact<M, T>(gestionnaire: &GestionnaireMessagerie, middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao + ValidateurX509,
        T: Transaction
{
    debug!("transaction_maj_contact Consommer transaction : {:?}", &transaction);
    let uuid_transaction = transaction.get_uuid_transaction().to_owned();

    let transaction_contact: Contact = match transaction.clone().convertir::<Contact>() {
        Ok(t) => t,
        Err(e) => Err(format!("transactions.transaction_maj_contact Erreur conversion transaction : {:?}", e))?
    };

    let user_id = {
        let certificat = match transaction.get_enveloppe_certificat() {
            Some(c) => c,
            None => Err(format!("transactions.transaction_initialiser_profil Certificat invalide/non charge"))?
        };
        match certificat.get_user_id()? {
            Some(u) => u,
            None => Err(format!("transactions.transaction_initialiser_profil user_id manquant du certificat"))?
        }
    };

    let doc_transaction = {
        let mut doc_transaction = match convertir_to_bson(&transaction_contact) {
            Ok(d) => d,
            Err(e) => Err(format!("transactions.transaction_maj_contact Erreur conversion transaction en bson : {:?}", e))?
        };
        doc_transaction.remove("uuid_contact");  // Enlever, utiliser comme cle
        doc_transaction
    };

    let collection = middleware.get_collection(NOM_COLLECTION_CONTACTS)?;
    let mut filtre = doc! {CHAMP_USER_ID: user_id};
    if let Some(uc) = transaction_contact.uuid_contact {
        filtre.insert("uuid_contact", &uc);
    }
    let options = UpdateOptions::builder()
        .upsert(true)
        .build();
    let ops = doc! {
        "$set": doc_transaction,
        "$setOnInsert": {CHAMP_CREATION: chrono::Utc::now(), "uuid_contact": uuid_transaction},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };

    match collection.update_one(filtre, ops, options).await {
        Ok(_) => (),
        Err(e) => Err(format!("transactions.transaction_maj_contact Erreur conversion transaction en bson : {:?}", e))?
    };

    middleware.reponse_ok()
}

async fn transaction_lu<M, T>(gestionnaire: &GestionnaireMessagerie, middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao + ValidateurX509,
        T: Transaction
{
    debug!("transaction_maj_contact Consommer transaction : {:?}", &transaction);
    let uuid_transaction = transaction.get_uuid_transaction().to_owned();

    let transaction_lu: CommandeLu = match transaction.clone().convertir::<CommandeLu>() {
        Ok(t) => t,
        Err(e) => Err(format!("transactions.transaction_maj_contact Erreur conversion transaction : {:?}", e))?
    };

    let user_id = {
        let certificat = match transaction.get_enveloppe_certificat() {
            Some(c) => c,
            None => Err(format!("transactions.transaction_initialiser_profil Certificat invalide/non charge"))?
        };
        match certificat.get_user_id()? {
            Some(u) => u,
            None => Err(format!("transactions.transaction_initialiser_profil user_id manquant du certificat"))?
        }
    };

    let flag_lu = transaction_lu.lu;
    let uuid_message = transaction_lu.uuid_transaction;
    let date_lu = match flag_lu {
        true => Some(transaction.get_estampille()),
        false => None
    };

    let collection = middleware.get_collection(NOM_COLLECTION_INCOMING)?;
    let filtre = doc! {CHAMP_USER_ID: user_id, TRANSACTION_CHAMP_UUID_TRANSACTION: uuid_message};
    let ops = doc! {
        "$set": {"lu": flag_lu, "lu_date": date_lu},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };

    match collection.update_one(filtre, ops, None).await {
        Ok(r) => {
            if r.matched_count != 1 {
                let reponse = match middleware.formatter_reponse(json!({"ok": false, "code": 500, "err": "Erreur maj flag lu"}), None) {
                    Ok(r) => return Ok(Some(r)),
                    Err(e) => Err(format!("transactions.transaction_maj_contact Erreur preparation reponse. Erreur de mise a jour flag lu."))?
                };

            }
        },
        Err(e) => Err(format!("transactions.transaction_maj_contact Erreur conversion transaction en bson : {:?}", e))?
    };

    middleware.reponse_ok()
}
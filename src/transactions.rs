use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::convert::TryInto;

use log::{debug, info, error, warn};
use millegrilles_common_rust::{chrono, serde_json, serde_json::json};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::{bson, bson::{doc, Document}};
use millegrilles_common_rust::bson::{Array, Bson};
use millegrilles_common_rust::bson::serde_helpers::deserialize_chrono_datetime_from_bson_datetime;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::common_messages::TransactionRetirerSubscriptionWebpush;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::constantes::Securite::{L2Prive, L4Secure};
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille, MessageSerialise};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::middleware::{map_msg_to_bson, map_serializable_to_bson, sauvegarder_traiter_transaction};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, MongoDao, verifier_erreur_duplication_mongo};
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, FindOptions, ReturnDocument, UpdateOptions};
use millegrilles_common_rust::recepteur_messages::{MessageValideAction, TypeMessage};
use millegrilles_common_rust::redis::ToRedisArgs;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::{Map, Value};
use millegrilles_common_rust::transactions::Transaction;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::verificateur::{ValidationOptions, VerificateurMessage};
use crate::communs::url_to_mongokey;

use crate::constantes::*;
use crate::gestionnaire::GestionnaireMessagerie;
use crate::message_structs::*;
use crate::pompe_messages::{emettre_evenement_pompe, marquer_outgoing_resultat, PompeMessages, verifier_message_complete};

const CHAMP_NOTIFICATIONS_ACTIVES: &str = "notifications_actives";
const CHAMP_DERNIERE_NOTIFICATION: &str = "derniere_notification";
const CHAMP_WEBPUSH_SUBSCRIPTIONS: &str = "webpush_subscriptions";

pub async fn consommer_transaction<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("transactions.consommer_transaction Consommer transaction : {:?}", &m.message);

    // Autorisation
    match m.action.as_str() {
        // 4.secure - doivent etre validees par une commande
        TRANSACTION_POSTER |
        TRANSACTION_RECEVOIR |
        TRANSACTION_INITIALISER_PROFIL |
        TRANSACTION_MAJ_CONTACT |
        TRANSACTION_LU |
        TRANSACTION_TRANSFERT_COMPLETE |
        TRANSACTION_SUPPRIMER_MESSAGES |
        TRANSACTION_SUPPRIMER_CONTACTS |
        TRANSACTION_CONFIRMER_TRANMISSION_MILLEGRILLE |
        TRANSACTION_SAUVEGARDER_CLEWEBPUSH_NOTIFICATIONS |
        TRANSACTION_SAUVEGARDER_USAGER_CONFIG_NOTIFICATIONS |
        TRANSACTION_SAUVEGARDER_SUBSCRIPTION_WEBPUSH |
        TRANSACTION_RETIRER_SUBSCRIPTION_WEBPUSH
        => {
            match m.verifier_exchanges(vec![Securite::L4Secure]) {
                true => Ok(()),
                false => Err(format!("transactions.consommer_transaction: Message autorisation invalide (pas 4.secure)"))
            }?;
        },
        _ => Err(format!("transactions.consommer_transaction: Mauvais type d'action pour une transaction : {}", m.action))?,
    }

    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

pub async fn aiguillage_transaction<M, T>(gestionnaire: &GestionnaireMessagerie, middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao + VerificateurMessage,
        T: Transaction
{
    let action = match transaction.get_routage().action.as_ref() {
        Some(inner) => inner.as_str(),
        None => Err(format!("transactions.aiguillage_transaction: Transaction {} n'a pas d'action", transaction.get_uuid_transaction()))?
    };

    match action {
        TRANSACTION_POSTER => transaction_poster(gestionnaire, middleware, transaction).await,
        TRANSACTION_RECEVOIR => transaction_recevoir(gestionnaire, middleware, transaction).await,
        TRANSACTION_INITIALISER_PROFIL => transaction_initialiser_profil(gestionnaire, middleware, transaction).await,
        TRANSACTION_MAJ_CONTACT => transaction_maj_contact(gestionnaire, middleware, transaction).await,
        TRANSACTION_LU => transaction_lu(gestionnaire, middleware, transaction).await,
        TRANSACTION_TRANSFERT_COMPLETE => transfert_complete(gestionnaire, middleware, transaction).await,
        TRANSACTION_SUPPRIMER_MESSAGES => supprimer_message(gestionnaire, middleware, transaction).await,
        TRANSACTION_SUPPRIMER_CONTACTS => supprimer_contacts(gestionnaire, middleware, transaction).await,
        TRANSACTION_CONFIRMER_TRANMISSION_MILLEGRILLE => confirmer_transmission_millegrille(gestionnaire, middleware, transaction).await,
        TRANSACTION_CONSERVER_CONFIGURATION_NOTIFICATIONS => conserver_configuration_notifications(gestionnaire, middleware, transaction).await,
        TRANSACTION_SAUVEGARDER_CLEWEBPUSH_NOTIFICATIONS => sauvegarder_clewebpush_notifications(gestionnaire, middleware, transaction).await,
        TRANSACTION_SAUVEGARDER_USAGER_CONFIG_NOTIFICATIONS => sauvegarder_usager_config_notifications(gestionnaire, middleware, transaction).await,
        TRANSACTION_SAUVEGARDER_SUBSCRIPTION_WEBPUSH => sauvegarder_subscription_webpush(gestionnaire, middleware, transaction).await,
        TRANSACTION_RETIRER_SUBSCRIPTION_WEBPUSH => retirer_subscription_webpush(gestionnaire, middleware, transaction).await,
        _ => Err(format!("core_backup.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.get_uuid_transaction(), action)),
    }
}

async fn transaction_poster<M, T>(gestionnaire: &GestionnaireMessagerie, middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_poster Consommer transaction : {:?}", &transaction);
    let uuid_transaction = transaction.get_uuid_transaction();
    let estampille = transaction.get_estampille();
    let user_id = match transaction.get_enveloppe_certificat() {
        Some(e) => e.get_user_id()?.to_owned(),
        None => None
    };

    let transaction_poster: CommandePoster = match transaction.clone().convertir::<CommandePoster>() {
        Ok(t) => t,
        Err(e) => Err(format!("messagerie.transaction_poster Erreur conversion transaction : {:?}", e))?
    };

    // Utiliser le id du message (dans l'enveloppe poster) comme reference du message
    let message_id = transaction_poster.message.id.clone();
    let estampille_message = transaction_poster.message.estampille.clone();

    // Convertir le contenu du message en bson
    let message_contenu = match convertir_to_bson(transaction_poster.message.clone()) {
        Ok(inner) => inner,
        Err(e) => Err(format!("messagerie.transaction_poster Erreur conversion transaction {}", uuid_transaction))?
    };

    // Conserver document dans outgoing et flags dans outgoing_processing
    let mut doc_outgoing = doc! {
        "message": message_contenu,

        // Identificateurs
        // "message_id": &message_id,
        "user_id": user_id.as_ref(),
        "fuuids": &transaction_poster.fuuids,

        // Flags
        "supprime": false,
        "transfert_complete": false,
    };

    // let mut doc_bson_transaction = match convertir_to_bson(&transaction_poster) {
    //     Ok(d) => d,
    //     Err(e) => Err(format!("transactions.transaction_poster Erreur conversion transaction en bson : {:?}", e))?
    // };
    // let mut doc_outgoing = match doc_bson_transaction.get_document("message") {
    //     Ok(m) => m.to_owned(),
    //     Err(e) => Err(format!("transactions.transaction_poster Erreur conversion message en doc_bson : {:?}", e))?
    // };
    // doc_outgoing.insert("uuid_transaction", &uuid_message);
    // doc_outgoing.insert("user_id", &user_id);
    // doc_outgoing.insert("supprime", false);
    // doc_outgoing.insert("transfert_complete", false);
    // doc_outgoing.insert(CHAMP_DATE_ENVOI, DateEpochSeconds::from(estampille.to_owned()));

    // Ajouter map destinataires
    let mut map_destinataires = Map::new();
    for dest in &transaction_poster.destinataires {
        // Remplacer "." par "," pour supporter acces cles MongoDB
        map_destinataires.insert(dest.replace(".", ","), Value::Null);
    }
    let map_destinataires = match convertir_to_bson(map_destinataires) {
        Ok(m) => m,
        Err(e) => Err(format!("transactions.transaction_poster Erreur conversion map_destinataires en doc_bson : {:?}", e))?
    };
    doc_outgoing.insert("destinataires", map_destinataires);

    let mut dns_adresses: HashSet<String> = HashSet::new();
    let mut destinataires = Array::new();
    let liste_destinataires = transaction_poster.get_destinataires();
    for dest in liste_destinataires.into_iter() {
        let mut dest_split = dest.split(CONST_ADRESSE_SEPARATEUR_HOST);
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

        if user.starts_with(CONST_ADRESSE_PREFIXE_USAGER) {
            user = user.trim_start_matches(CONST_ADRESSE_PREFIXE_USAGER);
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
        "transaction_id": uuid_transaction,
        CHAMP_UUID_MESSAGE: &message_id,
        "destinataires": destinataires,
        "user_id": user_id,
        "dns_unresolved": &dns_adresses,
        "idmgs_mapping": doc!{},
        "idmgs_unprocessed": Vec::<String>::new(),
        "created": chrono::Utc::now(),
        "fuuids": transaction_poster.fuuids,
    };

    // Inserer document de message dans outgoing
    {
        let collection = middleware.get_collection(NOM_COLLECTION_OUTGOING)?;
        match collection.insert_one(doc_outgoing, None).await {
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
    match emettre_requete_resolve(middleware, uuid_transaction, &dns_adresses).await {
        Ok(()) => (),
        Err(e) => Err(format!("transactions.transaction_poster Erreur requete resolve idmg {:?}", e))?,
    }

    // Declencher pompe a messages si elle n'est pas deja active
    if let Err(e) = emettre_evenement_pompe(middleware, None).await {
        error!("transaction_poster Erreur declencher pompe de messages : {:?}", e);
    }

    let reponse = json!({
        "ok": true,
        "message_id": message_id
    });

    match middleware.formatter_reponse(reponse, None) {
        Ok(r) => Ok(Some(r)),
        Err(e) => Err(format!("transaction_poster Erreur preparation confirmat envoi message {} : {:?}", uuid_transaction, e))
    }

}

pub async fn emettre_requete_resolve<M>(middleware: &M, uuid_transaction: &str, dns: &Vec<String>)
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

    debug!("transactions.emettre_requete_resolve Demande resolve : {:?}", requete);
    let reponse = middleware.transmettre_requete(routage, &requete).await?;
    debug!("transactions.emettre_requete_resolve Reponse resolve topologie : {:?}", reponse);
    match reponse {
        TypeMessage::Valide(r) => {
            debug!("Reponse resolve idmg : {:?}", r);
            let contenu: ReponseTopologieResolveIdmg = r.message.parsed.map_contenu()?;
            debug!("Reponse resolve idmg contenu parsed : {:?}", contenu);
            traiter_outgoing_resolved(middleware, &contenu).await?;
        },
        _ => Err(format!("Erreur resolve idmg, mauvais type de reponse"))?
    }

    Ok(())
}

async fn traiter_outgoing_resolved<M>(middleware: &M, reponse: &ReponseTopologieResolveIdmg)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + MongoDao
{
    debug!("transactions.traiter_outgoing_resolved Reponse a traiter : {:?}", reponse);
    let collection = middleware.get_collection(NOM_COLLECTION_OUTGOING_PROCESSING)?;

    let mut idmgs: HashSet<String> = HashSet::new();

    if let Some(d) = &reponse.dns {

        let ts_courant = Utc::now().timestamp();

        for (dns, idmg_option) in d {
            let idmg = match idmg_option {
                Some(i) => i,
                None => {
                    info!("traiter_outgoing_resolved DNS inconnu : {:?}", dns);
                    continue
                }
            };

            idmgs.insert(idmg.to_owned());

            let filtre = doc! {"dns_unresolved": {"$all": [dns]}};
            let ops = doc! {
                "$set": {
                    format!("idmgs_mapping.{}.push_count", idmg): 0,
                    format!("idmgs_mapping.{}.next_push_time", idmg): ts_courant,
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

    if ! idmgs.is_empty() {
        emettre_evenement_pompe(middleware, Some(idmgs.into_iter().collect())).await?;
    }

    Ok(())
}

async fn transaction_recevoir<M, T>(gestionnaire: &GestionnaireMessagerie, middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao + ValidateurX509 + VerificateurMessage,
        T: Transaction
{
    debug!("transaction_recevoir Consommer transaction : {:?}", &transaction);
    let uuid_transaction = transaction.get_uuid_transaction().to_owned();

    let message_recevoir: DocumentRecevoirPost = match transaction.clone().convertir() {
        Ok(t) => t,
        Err(e) => Err(format!("transaction_recevoir Erreur conversion transaction : {:?}", e))?
    };
    let mut message_recevoir_serialise = match MessageSerialise::from_parsed(message_recevoir.message) {
        Ok(m) => Ok(m),
        Err(e) => Err(format!("transactions.transaction_recevoir Erreur mapping message serialise : {:?}", e))
    }?;

    let message_local = match message_recevoir_serialise.parsed.origine.as_ref() {
        Some(inner) => inner.as_str() == middleware.idmg(),
        None => true
    };

    // Charger certificat dans le message pour validation
    {
        let fingerprint = message_recevoir_serialise.parsed.pubkey.as_str();
        match middleware.get_certificat(fingerprint).await {
            Some(certificat) => {
                message_recevoir_serialise.certificat = Some(certificat);
            },
            None => Err(format!("transactions.transaction_recevoir Erreur mapping message serialise, certificat introuvable : {}", fingerprint))?
        }

        let resultat = match middleware.verifier_message(&mut message_recevoir_serialise, None) {
            Ok(inner) => inner,
            Err(e) => Err(format!("transactions.transaction_recevoir Erreur mapping message serialise : {:?}", e))?
        };
        match resultat.valide() {
            true => debug!("transactions.transaction_recevoir Message valide (OK)"),
            false => Err(format!("transactions.transaction_recevoir Erreur mapping message serialise, echec validation : {:?}", resultat))?
        }
    };

    // // Conserver message pour chaque destinataires locaux
    // //let transaction_poster: TransactionPoster = message_recevoir_serialise
    // let message_chiffre = message_enveloppe.message_chiffre;
    // let hachage_bytes = message_enveloppe.hachage_bytes;
    // let fingerprint_usager = message_enveloppe.fingerprint_certificat;
    // let attachments = message_enveloppe.attachments;
    //
    // // let destinataires = match message_recevoir.destinataires_user_id.as_ref() {
    // //     Some(inner) => {
    // //         if inner.len() > 0 {
    // //             inner
    // //         } else {
    // //             Err(format!("transactions.transaction_recevoir Erreur reception message, aucun destinataire_user_id (len==0)"))?
    // //         }
    // //     },
    // //     None => Err(format!("transactions.transaction_recevoir Erreur reception message, aucun destinataire_user_id"))?
    // // };
    //
    // // Retirer la part serveur du destinataire
    // // let mut destinataires_resultat = HashMap::new();
    // // let (destinataires_nomusager, destinataires_adresses) = {
    // //     let mut destinataires = Vec::new();
    // //     let mut destinataires_adresses = HashMap::new();
    // //     for adresse in &message_recevoir.destinataires {
    // //         match AdresseMessagerie::new(adresse.as_str()) {
    // //             Ok(a) => {
    // //                 destinataires_adresses.insert(a.user.clone(), adresse.to_owned());
    // //                 destinataires_resultat.insert(adresse.to_owned(), 404);  // Defaut usager inconnu
    // //                 destinataires.push(a.user);
    // //             },
    // //             Err(e) => {
    // //                 // Verifier si c'est un nom d'usager interne
    // //
    // //                 info!("Erreur parsing adresse {}, on l'ignore", adresse)
    // //             }
    // //         }
    // //     }
    // //     (destinataires, destinataires_adresses)
    // // };
    //
    // // Resolve destinataires nom_usager => user_id
    // let destinataires = match message_recevoir.destinataires_user_id.as_ref() {
    //     Some(inner) => {
    //         if inner.len() > 0 {
    //             inner
    //         } else {
    //             Err(format!("transactions.transaction_recevoir Erreur reception message, aucun destinataire_user_id (len==0)"))?
    //         }
    //     },
    //     None => Err(format!("transactions.transaction_recevoir Erreur reception message, aucun destinataire_user_id"))?
    // };
    //
    // // let reponse_mappee: ReponseUseridParNomUsager = {
    // //     let requete_routage = RoutageMessageAction::builder("CoreMaitreDesComptes", "getUserIdParNomUsager")
    // //         .exchanges(vec![Securite::L4Secure])
    // //         .build();
    // //     let requete = json!({"noms_usagers": destinataires_nomusager});
    // //     debug!("transaction_recevoir Requete {:?} pour user names : {:?}", requete_routage, requete);
    // //     let reponse = middleware.transmettre_requete(requete_routage, &requete).await?;
    // //     debug!("transaction_recevoir Reponse mapping users : {:?}", reponse);
    // //     match reponse {
    // //         TypeMessage::Valide(m) => {
    // //             match m.message.parsed.map_contenu(None) {
    // //                 Ok(m) => m,
    // //                 Err(e) => Err(format!("pompe_messages.transaction_recevoir Erreur mapping reponse requete noms usagers : {:?}", e))?
    // //             }
    // //         },
    // //         _ => Err(format!("pompe_messages.transaction_recevoir Erreur mapping reponse requete noms usagers, mauvais type reponse"))?
    // //     }
    // // };
    //
    // let collection = middleware.get_collection(NOM_COLLECTION_INCOMING)?;
    //
    // let certificat_usager = middleware.get_certificat(fingerprint_usager.as_str()).await;
    // let certificat_usager_pem: Vec<String> = match certificat_usager {
    //     Some(c) => {
    //         let fp_certs = c.get_pem_vec();
    //         fp_certs.into_iter().map(|c| c.pem).collect()
    //     },
    //     None => Err(format!("transactions.transaction_recevoir Erreur insertion message {}, certificat {} introuvable", uuid_transaction, fingerprint_usager))?
    // };
    //
    // let attachments_recus = match attachments.as_ref() {
    //     // Si on a des attachments et le message est local : true.
    //     // Sinon aucuns attachments => true, au moins 1 => false
    //     Some(a) => message_local || a.is_empty(),
    //     None => true
    // };
    //
    // let attachments_bson = match attachments.as_ref() {
    //     Some(a) => {
    //         let mut attachments_bson = doc!{};
    //         for fuuid in a {
    //             // Si message local, on marque recu. Sinon on met false.
    //             attachments_bson.insert(fuuid.to_owned(), message_local);
    //         }
    //         Some(attachments_bson)
    //     },
    //     None => None
    // };
    //
    // let mut destinataires_resultat = HashMap::new();
    // let now: Bson = DateEpochSeconds::now().into();
    // for d in destinataires {
    //     match d.user_id.as_ref() {
    //         Some(u) => {
    //             // Sauvegarder message pour l'usager
    //             debug!("transaction_recevoir Sauvegarder message pour usager : {}", u);
    //
    //             let mut doc_user_reception = doc! {
    //                 "user_id": u,
    //                 "uuid_transaction": &uuid_transaction,
    //                 "uuid_message": &uuid_message,
    //                 "lu": false,
    //                 CHAMP_SUPPRIME: false,
    //                 "date_reception": &now,
    //                 "date_ouverture": None::<&str>,
    //                 "certificat_message": &certificat_usager_pem,
    //                 "message_chiffre": &message_chiffre,
    //                 "hachage_bytes": &hachage_bytes,
    //                 CHAMP_ATTACHMENTS: &attachments_bson,
    //                 CHAMP_ATTACHMENTS_TRAITES: &attachments_recus,
    //             };
    //
    //             if let Some(cm) = certificat_millegrille_pem.as_ref() {
    //                 doc_user_reception.insert("certificat_millegrille", cm);
    //             }
    //
    //             debug!("transaction_recevoir Inserer message {:?}", doc_user_reception);
    //             match collection.insert_one(&doc_user_reception, None).await {
    //                 Ok(_r) => {
    //                     // Marquer usager comme trouve et traite
    //                     if let Some(adresse_usager) = d.adresse.as_ref() {
    //                         destinataires_resultat.insert(adresse_usager.to_owned(), 201);  // Message cree pour usager
    //                     }
    //                 },
    //                 Err(e) => {
    //                     let erreur_duplication = verifier_erreur_duplication_mongo(&*e.kind);
    //                     if erreur_duplication {
    //                         warn!("transaction_recevoir Duplication message externe recu, on l'ignore : {:?}", doc_user_reception);
    //                         if let Some(adresse_usager) = d.adresse.as_ref() {
    //                             destinataires_resultat.insert(adresse_usager.to_owned(), 200);  // Message deja traite
    //                         }
    //                         return middleware.reponse_ok();
    //                     } else {
    //                         if let Some(adresse_usager) = d.adresse.as_ref() {
    //                             destinataires_resultat.insert(adresse_usager.to_owned(), 500);  // Erreur de traitement
    //                         }
    //                         Err(format!("transactions.transaction_recevoir Erreur insertion message {} pour usager {} : {:?}", uuid_transaction, u, e))?
    //                     }
    //                 }
    //             }
    //
    //             // Evenement de nouveau message pour front-end, notifications
    //             if let Ok(m) = convertir_bson_deserializable::<MessageIncoming>(doc_user_reception) {
    //                 // let message_mappe: MessageIncoming =
    //                 let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_NOUVEAU_MESSAGE)
    //                     .exchanges(vec![L2Prive])
    //                     .partition(u)
    //                     .build();
    //                 middleware.emettre_evenement(routage, &m).await?;
    //             }
    //         },
    //         None => {
    //             if let Some(adresse_usager) = d.adresse.as_ref() {
    //                 destinataires_resultat.insert(adresse_usager.to_owned(), 404);  // Usager inconnu
    //             }
    //         }
    //     }
    // }
    //
    // if message_local {
    //     // Marquer le message comme traiter dans "outgoing local"
    //     let destinataires: Vec<ConfirmerDestinataire> = destinataires_resultat.iter().map(|(adresse, code)|{
    //         ConfirmerDestinataire {code: code.to_owned(), destinataire: adresse.to_owned()}
    //     }).collect();
    //     marquer_outgoing_resultat(
    //         middleware,
    //         uuid_message.as_str(),
    //         idmg_local.as_str(),
    //         Some(&destinataires),
    //         true
    //     ).await?;
    // }
    //
    // if ! attachments_recus {
    //     if let Some(a) = attachments.as_ref() {
    //         debug!("transaction_recevoir Emettre une verification aupres de fichiers pour existance de {:?}", attachments);
    //         let commande = CommandeVerifierExistanceFuuidsMessage { uuid_message: uuid_message.clone(), fuuids: a.to_owned() };
    //         let routage = RoutageMessageAction::builder(DOMAINE_NOM, "fuuidVerifierExistance")
    //             .exchanges(vec![L4Secure])
    //             .build();
    //         middleware.transmettre_commande(routage, &commande, false).await?;
    //     }
    // }
    //
    // if let Err(e) = emettre_notifications(
    //     middleware, destinataires, uuid_transaction.as_str(), uuid_message.as_str()).await {
    //     warn!("transaction_recevoir Erreur emission notifications : {:?}", e);
    // }
    //
    // let reponse = json!({"ok": true /*, "usagers": destinataires_resultat*/});
    // match middleware.formatter_reponse(&reponse, None) {
    //     Ok(r) => Ok(Some(r)),
    //     Err(e) => Err(format!("transactions.transaction_recevoir Erreur formattage reponse : {:?}", e))?
    // }
    todo!("fix me");
}

pub async fn emettre_notifications<M>(middleware: &M, usagers: &Vec<DestinataireInfo>, uuid_transaction: &str, uuid_message: &str)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("emettre_notifications uuid_transaction {}, uuid_message {}", uuid_transaction, uuid_message);
    // Trouver user_ids avec notifications activees, emettre trigger
    let mut user_ids = Vec::new();
    for d in usagers {
        if let Some(u) = d.user_id.as_ref() {
            user_ids.push(u.as_str());
        }
    }

    let collection_profils = middleware.get_collection(NOM_COLLECTION_PROFILS)?;
    let options = FindOptions::builder()
        .projection(doc!{CHAMP_USER_ID: true})
        .build();
    let filtre = doc! {CHAMP_NOTIFICATIONS_ACTIVES: true, CHAMP_USER_ID: {"$in": user_ids}};
    let mut curseur = collection_profils.find(filtre, Some(options)).await?;
    while let Some(res) = curseur.next().await {
        let row = res?;
        let user_id = match row.get(CHAMP_USER_ID) {
            Some(u) => match u.as_str() {
                Some(u) => u,
                None => continue
            },
            None => continue
        };
        ajouter_notification_usager(middleware, user_id, uuid_transaction, uuid_message).await?;
    }

    Ok(())
}

async fn ajouter_notification_usager<M>(middleware: &M, user_id: &str, uuid_transaction: &str, uuid_message: &str)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("Conserver trigger notification pour {} sur uuid_transaction {}, uuid_message {}", user_id, uuid_transaction, uuid_message);

    let filtre = doc! { CHAMP_USER_ID: user_id };
    let collection = middleware.get_collection(NOM_COLLECTION_NOTIFICATIONS_OUTGOING)?;

    let set_on_insert_ops = doc! {
        CHAMP_CREATION: Utc::now(),
        CHAMP_USER_ID: user_id,
        CHAMP_EXPIRATION_LOCK_NOTIFICATIONS: Utc::now(),
    };

    let push_ops = doc! {
        CHAMP_UUID_TRANSACTIONS_NOTIFICATIONS: uuid_transaction,
    };

    let ops = doc! {
        "$setOnInsert": set_on_insert_ops,
        "$push": push_ops,
        "$set": {
            CHAMP_NOTIFICATIONS_PENDING: true,
        },
        "$currentDate": {
            CHAMP_MODIFICATION: true,
            CHAMP_DERNIERE_NOTIFICATION: true,
        }
    };

    let options = UpdateOptions::builder().upsert(true).build();
    collection.update_one(filtre, ops, Some(options)).await?;

    Ok(())
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
    let adresse = transaction_initialiser_profil.adresse.as_str();

    let certificat = match transaction.get_enveloppe_certificat() {
        Some(c) => c,
        None => Err(format!("transactions.transaction_initialiser_profil Certificat invalide/non charge"))?
    };
    let user_id = transaction_initialiser_profil.user_id.as_str();

    let collection = middleware.get_collection(NOM_COLLECTION_PROFILS)?;
    let filtre = doc! {CHAMP_USER_ID: user_id};
    let options = FindOneAndUpdateOptions::builder()
        .upsert(true)
        .return_document(ReturnDocument::After)
        .build();
    let ops = doc! {
        "$set": {
            "adresses": [adresse],
            "cle_ref_hachage_bytes": &transaction_initialiser_profil.cle_ref_hachage_bytes,
        },
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

async fn transaction_maj_contact<M, T>(gestionnaire: &GestionnaireMessagerie, middleware: &M, transaction: T)
    -> Result<Option<MessageMilleGrille>, String>
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
    let options = FindOneAndUpdateOptions::builder()
        .return_document(ReturnDocument::After)
        .upsert(true)
        .build();
    let ops = doc! {
        "$set": doc_transaction,
        "$setOnInsert": {CHAMP_CREATION: chrono::Utc::now(), "uuid_contact": uuid_transaction, CHAMP_SUPPRIME: false},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };

    let contact = match collection.find_one_and_update(filtre, ops, options).await {
        Ok(c) => c,
        Err(e) => Err(format!("transactions.transaction_maj_contact Erreur conversion transaction en bson : {:?}", e))?
    };

    if let Some(c) = contact {
        // Emettre evenement contact
        let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_MAJ_CONTACT)
            .exchanges(vec![L2Prive])
            .partition(user_id)
            .build();
        let contact_mappe: Contact = match convertir_bson_deserializable(c) {
            Ok(c) => c,
            Err(e) => Err(format!("transactions.transaction_maj_contact Erreur convertir_bson_deserializable contact : {:?}", e))?
        };
        middleware.emettre_evenement(routage, &contact_mappe).await?;
    }

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
    todo!("fix me");
    // let filtre = doc! {CHAMP_USER_ID: user_id, TRANSACTION_CHAMP_UUID_TRANSACTION: &uuid_message};
    // let ops = doc! {
    //     "$set": {"lu": flag_lu, "lu_date": date_lu},
    //     "$currentDate": {CHAMP_MODIFICATION: true},
    // };
    //
    // match collection.update_one(filtre, ops, None).await {
    //     Ok(r) => {
    //         if r.matched_count != 1 {
    //             let reponse = match middleware.formatter_reponse(json!({"ok": false, "code": 500, "err": "Erreur maj flag lu"}), None) {
    //                 Ok(r) => return Ok(Some(r)),
    //                 Err(e) => Err(format!("transactions.transaction_maj_contact Erreur preparation reponse. Erreur de mise a jour flag lu."))?
    //             };
    //         }
    //     },
    //     Err(e) => Err(format!("transactions.transaction_maj_contact Erreur conversion transaction en bson : {:?}", e))?
    // };
    //
    // // Emettre evenement lu
    // {
    //     let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_MESSAGE_LU)
    //         .exchanges(vec![L2Prive])
    //         .partition(user_id)
    //         .build();
    //     let evenement_lu = json!({
    //         "lus": {&uuid_message: flag_lu},
    //     });
    //     middleware.emettre_evenement(routage, &evenement_lu).await?;
    // }
    //
    // middleware.reponse_ok()
}

async fn transfert_complete<M, T>(gestionnaire: &GestionnaireMessagerie, middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao + ValidateurX509,
        T: Transaction
{
    debug!("transfert_complete Consommer transaction : {:?}", &transaction);

    let transaction_mappee = match transaction.convertir::<TransactionTransfertComplete>() {
        Ok(t) => t,
        Err(e) => Err(format!("transactions.transfert_complete Erreur conversion transaction : {:?}", e))?
    };

    let uuid_message = transaction_mappee.uuid_message.as_str();
    let filtre = doc! {CHAMP_UUID_MESSAGE: uuid_message};
    let mut unset_ops = doc!{};
    if let Some(m) = transaction_mappee.message_complete {
        if m {
            unset_ops.insert("dns_unresolved", true);
            unset_ops.insert("idmgs_unprocessed", true);
        }
    }

    if let Some(a) = transaction_mappee.attachments_completes {
        if a {
            unset_ops.insert("idmgs_attachments_unprocessed", true);
        }
    }

    let collection = middleware.get_collection(NOM_COLLECTION_OUTGOING_PROCESSING)?;
    let ops = doc! {
        "$unset": unset_ops,
        "$currentDate": {CHAMP_LAST_PROCESSED: true},
    };
    let options = FindOneAndUpdateOptions::builder()
        .return_document(ReturnDocument::After)
        .build();

    let outgoing_processing: DocOutgointProcessing = match collection.find_one_and_update(filtre, ops, options).await {
        Ok(r) => match r {
            Some(d) => match convertir_bson_deserializable(d) {
                Ok(d) => d,
                Err(e) => Err(format!("transactions.transfert_complete Erreur conversion resultat pour transfert complete {} : {:?}", uuid_message, e))?
            },
            None => {
                // Le doc n'existe pas, probablement un vieux message durant regeneration.
                return Ok(None)
            }
        },
        Err(e) => Err(format!("transactions.transfert_complete Erreur update pour transfert complete {} : {:?}", uuid_message, e))?
    };

    let message_complete = verifier_message_complete(middleware, &outgoing_processing);
    if message_complete {
        debug!("transfert_complete Conserve flag message complete dans outgoing");
        let filtre = doc!{
            "uuid_transaction": uuid_message,
            "user_id": outgoing_processing.user_id.as_ref(),
        };
        let ops = doc!{
            "$set": {"transfert_complete": true},
            "$currentDate": {CHAMP_MODIFICATION: true}
        };
        let collection = middleware.get_collection(NOM_COLLECTION_OUTGOING)?;
        match collection.update_one(filtre, ops, None).await {
            Ok(_r) => (),
            Err(e) => error!("transactions.transfert_complete Erreur update message outgoing : {:?}", e)
        };

        debug!("transfert_complete Emettre evenement message complete");
        if let Some(user_id) = outgoing_processing.user_id {
            let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_CONFIRMER_MESSAGE_COMPLETE)
                .exchanges(vec![Securite::L2Prive])
                .partition(user_id.clone())
                .build();
            let message = ConfirmerMessageComplete { user_id, uuid_message: uuid_message.to_owned() };
            middleware.emettre_evenement(routage, &message).await?;
        }
    }

    Ok(None)
}

async fn supprimer_message<M, T>(gestionnaire: &GestionnaireMessagerie, middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao + ValidateurX509,
        T: Transaction
{
    debug!("supprimer_message Consommer transaction : {:?}", &transaction);

    let uuid_transaction = transaction.get_uuid_transaction().to_owned();
    let user_id = match transaction.get_enveloppe_certificat() {
        Some(e) => match e.get_user_id()?.to_owned() {
            Some(u) => u,
            None => Err(format!("transactions.supprimer_message Certificat sans user_id, transaction {} invalide", uuid_transaction))?
        },
        None => Err(format!("transactions.supprimer_message Message sans certificat, transaction {} invalide", uuid_transaction))?
    };

    let transaction_mappee = match transaction.convertir::<TransactionSupprimerMessage>() {
        Ok(t) => t,
        Err(e) => Err(format!("transactions.supprimer_message Erreur conversion transaction : {:?}", e))?
    };

    let uuid_transactions = transaction_mappee.uuid_transactions;
    todo!("fix me");
    // let filtre = doc! {CHAMP_USER_ID: &user_id, TRANSACTION_CHAMP_UUID_TRANSACTION: {"$in": &uuid_transactions}};
    // let ops = doc! {
    //     "$set": { CHAMP_SUPPRIME: true },
    //     "$currentDate": {CHAMP_MODIFICATION: true},
    // };
    //
    // debug!("supprimer_message filtre : {:?}, ops: {:?}", filtre, ops);
    //
    // let collection = middleware.get_collection(NOM_COLLECTION_INCOMING)?;
    // match collection.update_many(filtre, ops, None).await {
    //     Ok(r) => debug!("supprimer_message Resultat : {:?}", r),
    //     Err(e) => Err(format!("transactions.supprimer_message Erreur update pour transfert complete {} : {:?}", uuid_transaction, e))?
    // }
    //
    // let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_MESSAGES_SUPPRIMES)
    //     .exchanges(vec![L2Prive])
    //     .partition(&user_id)
    //     .build();
    // let evenement_supprime = json!({
    //     "uuid_transactions": &uuid_transactions,
    // });
    // middleware.emettre_evenement(routage, &evenement_supprime).await?;
    //
    // middleware.reponse_ok()
}

async fn supprimer_contacts<M, T>(gestionnaire: &GestionnaireMessagerie, middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao + ValidateurX509,
        T: Transaction
{
    debug!("supprimer_contacts Consommer transaction : {:?}", &transaction);

    let uuid_transaction = transaction.get_uuid_transaction().to_owned();
    let user_id = match transaction.get_enveloppe_certificat() {
        Some(e) => match e.get_user_id()?.to_owned() {
            Some(u) => u,
            None => Err(format!("transactions.supprimer_contacts Certificat sans user_id, transaction {} invalide", uuid_transaction))?
        },
        None => Err(format!("transactions.supprimer_contacts Message sans certificat, transaction {} invalide", uuid_transaction))?
    };

    let transaction_mappee = match transaction.convertir::<TransactionSupprimerContacts>() {
        Ok(t) => t,
        Err(e) => Err(format!("transactions.supprimer_contacts Erreur conversion transaction : {:?}", e))?
    };

    let uuid_contacts = transaction_mappee.uuid_contacts;
    let filtre = doc! {CHAMP_USER_ID: &user_id, CHAMP_UUID_CONTACT: {"$in": &uuid_contacts}};
    let ops = doc! {
        "$set": { CHAMP_SUPPRIME: true },
        "$currentDate": {CHAMP_MODIFICATION: true},
    };

    debug!("supprimer_contacts filtre : {:?}, ops: {:?}", filtre, ops);

    let collection = middleware.get_collection(NOM_COLLECTION_CONTACTS)?;
    match collection.update_many(filtre, ops, None).await {
        Ok(r) => debug!("supprimer_contacts Resultat : {:?}", r),
        Err(e) => Err(format!("transactions.supprimer_contacts Erreur update pour transfert complete {} : {:?}", uuid_transaction, e))?
    }

    let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_CONTACTS_SUPPRIMES)
        .exchanges(vec![L2Prive])
        .partition(&user_id)
        .build();
    let evenement_supprime = json!({
        CHAMP_UUID_CONTACTS: &uuid_contacts,
    });
    middleware.emettre_evenement(routage, &evenement_supprime).await?;

    middleware.reponse_ok()
}

async fn confirmer_transmission_millegrille<M, T>(gestionnaire: &GestionnaireMessagerie, middleware: &M, transaction: T)
    -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao + ValidateurX509,
        T: Transaction
{
    debug!("confirmer_transmission_millegrille Consommer transaction : {:?}", &transaction);
    let transaction_mappee = match transaction.convertir::<ConfirmerTransmissionMessageMillegrille>() {
        Ok(t) => t,
        Err(e) => Err(format!("transactions.confirmer_transmission_millegrille Erreur conversion transaction : {:?}", e))?
    };

    let filtre = doc!{
        "uuid_transaction": &transaction_mappee.uuid_message,
        "user_id": &transaction_mappee.user_id,
    };
    let mut set_ops = doc!{};
    for info_destinataire in &transaction_mappee.destinataires {
        // Remplacer "." par "," pour supporter acces cles MongoDB
        let destinataire = info_destinataire.destinataire.replace(".", ",");
        set_ops.insert(format!("destinataires.{}", destinataire), &info_destinataire.code);
    }
    let ops = doc! {
        "$set": set_ops,
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let collection = middleware.get_collection(NOM_COLLECTION_OUTGOING)?;
    match collection.update_one(filtre, ops, None).await {
        Ok(_d) => (),
        Err(e) => Err(format!("transactions.confirmer_transmission_millegrille Erreur sauvegarde etat outgoing"))?
    }

    middleware.reponse_ok()
}

async fn conserver_configuration_notifications<M, T>(gestionnaire: &GestionnaireMessagerie, middleware: &M, transaction: T)
    -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao + ValidateurX509,
        T: Transaction
{
    debug!("conserver_configuration_notifications Consommer transaction : {:?}", &transaction);
    let transaction_mappee = match transaction.convertir::<TransactionConserverConfigurationNotifications>() {
        Ok(t) => t,
        Err(e) => Err(format!("transactions.conserver_configuration_notifications Erreur conversion transaction : {:?}", e))?
    };

    let filtre = doc!{ CHAMP_CONFIG_KEY: CONFIG_KEY_NOTIFICATIONS };
    let set_on_insert = doc!{
        CHAMP_CREATION: Utc::now(),
        CHAMP_CONFIG_KEY: CONFIG_KEY_NOTIFICATIONS,
    };
    let mut set_ops = doc!{
        "email_from": transaction_mappee.email_from,
        "intervalle_min": transaction_mappee.intervalle_min,
    };
    if let Some(smtp) = transaction_mappee.smtp {
        match convertir_to_bson(smtp) {
            Ok(d) => { set_ops.insert("smtp", d); },
            Err(e) => Err(format!("transactions.conserver_configuration_notifications Erreur conversion config smtp : {:?}", e))?
        }
    }
    if let Some(webpush) = transaction_mappee.webpush {
        match convertir_to_bson(webpush) {
            Ok(d) => { set_ops.insert("webpush", d); },
            Err(e) => Err(format!("transactions.conserver_configuration_notifications Erreur conversion config webpush : {:?}", e))?
        }
    }

    let ops = doc! {
        "$set": set_ops,
        "$setOnInsert": set_on_insert,
        "$currentDate": {CHAMP_MODIFICATION: true},
    };

    let options = UpdateOptions::builder()
        .upsert(true)
        .build();

    let collection = middleware.get_collection(NOM_COLLECTION_CONFIGURATION)?;
    match collection.update_one(filtre, ops, Some(options)).await {
        Ok(_d) => (),
        Err(e) => Err(format!("transactions.conserver_configuration_notifications Erreur sauvegarde etat outgoing"))?
    }

    middleware.reponse_ok()
}

async fn sauvegarder_clewebpush_notifications<M, T>(gestionnaire: &GestionnaireMessagerie, middleware: &M, transaction: T)
    -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao + ValidateurX509,
        T: Transaction
{
    debug!("sauvegarder_clewebpush_notifications Consommer transaction : {:?}", &transaction);
    let transaction_mappee = match transaction.convertir::<TransactionCleWebpush>() {
        Ok(t) => t,
        Err(e) => Err(format!("transactions.sauvegarder_clewebpush_notifications Erreur conversion transaction : {:?}", e))?
    };

    let filtre = doc!{ CHAMP_CONFIG_KEY: CONFIG_KEY_CLEWEBPUSH };
    let set_on_insert = doc!{
        CHAMP_CREATION: Utc::now(),
        CHAMP_CONFIG_KEY: CONFIG_KEY_CLEWEBPUSH,
    };

    let data_chiffre = match convertir_to_bson(transaction_mappee.data_chiffre) {
        Ok(d) => d,
        Err(e) => Err(format!("transactions.sauvegarder_clewebpush_notifications Erreur conversion data_chiffre a bson : {:?}", e))?
    };

    let set_ops = doc!{
        "data_chiffre": data_chiffre,
        "cle_publique_pem": transaction_mappee.cle_publique_pem,
        "cle_publique_urlsafe": transaction_mappee.cle_publique_urlsafe,
    };

    let ops = doc! {
        "$set": set_ops,
        "$setOnInsert": set_on_insert,
        "$currentDate": {CHAMP_MODIFICATION: true},
    };

    let options = UpdateOptions::builder()
        .upsert(true)
        .build();

    let collection = middleware.get_collection(NOM_COLLECTION_CONFIGURATION)?;
    match collection.update_one(filtre, ops, Some(options)).await {
        Ok(_d) => (),
        Err(e) => Err(format!("transactions.sauvegarder_clewebpush_notifications Erreur sauvegarde cle web push : {:?}", e))?
    }

    middleware.reponse_ok()
}

async fn sauvegarder_usager_config_notifications<M, T>(gestionnaire: &GestionnaireMessagerie, middleware: &M, transaction: T)
    -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao + ValidateurX509,
        T: Transaction
{
    let user_id = match &transaction.get_enveloppe_certificat() {
        Some(c) => match c.get_user_id()? {
            Some(u) => u.to_owned(),
            None => Err(format!("Certificat sans user_id"))?
        },
        None => Err(format!("Certificat sans user_id"))?
    };

    debug!("sauvegarder_usager_config_notifications Consommer transaction : {:?}", &transaction);
    let transaction_mappee = match transaction.convertir::<TransactionSauvegarderUsagerConfigNotifications>() {
        Ok(t) => t,
        Err(e) => Err(format!("transactions.sauvegarder_usager_config_notifications Erreur conversion transaction : {:?}", e))?
    };

    let filtre = doc!{ CHAMP_USER_ID: &user_id };

    let email_actif = match transaction_mappee.email_actif {
        Some(e) => e,
        None => false
    };

    let email_chiffre = match convertir_to_bson(transaction_mappee.email_chiffre) {
        Ok(e) => e,
        Err(e) => Err(format!("transactions.sauvegarder_usager_config_notifications Erreur conversion data_chiffre en bson {:?}", e))?
    };

    let mut set_ops = doc!{
        "email_actif": email_actif,
        "email_chiffre": email_chiffre,
    };
    if email_actif == true {
        // Activer notifications pour le profil usager
        set_ops.insert(CHAMP_NOTIFICATIONS_ACTIVES, true);
    }

    let ops = doc! {
        "$set": set_ops,
        "$currentDate": {CHAMP_MODIFICATION: true},
    };

    let collection = middleware.get_collection(NOM_COLLECTION_PROFILS)?;
    match collection.update_one(filtre, ops, None).await {
        Ok(_d) => (),
        Err(e) => Err(format!("transactions.sauvegarder_usager_config_notifications Erreur sauvegarde config usager notifications : {:?}", e))?
    }

    if ! email_actif {
        // Verifier si on desactive les notifications
        verifier_toggle_notifications_actives(middleware, user_id.as_str()).await?;
    }

    middleware.reponse_ok()
}

async fn sauvegarder_subscription_webpush<M, T>(gestionnaire: &GestionnaireMessagerie, middleware: &M, transaction: T)
    -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao + ValidateurX509,
        T: Transaction
{
    let user_id = match &transaction.get_enveloppe_certificat() {
        Some(c) => match c.get_user_id()? {
            Some(u) => u.to_owned(),
            None => Err(format!("Certificat sans user_id"))?
        },
        None => Err(format!("Certificat sans user_id"))?
    };

    debug!("sauvegarder_subscription_webpush Consommer transaction : {:?}", &transaction);
    let transaction_mappee = match transaction.convertir::<TransactionSauvegarderSubscriptionWebpush>() {
        Ok(t) => t,
        Err(e) => Err(format!("transactions.sauvegarder_subscription_webpush Erreur conversion transaction : {:?}", e))?
    };

    let filtre = doc!{ CHAMP_USER_ID: user_id };

    // let addtoset_ops = doc!{
    //     "webpush_endpoints": transaction_mappee.endpoint
    // };

    let cle_endpoint = url_to_mongokey(transaction_mappee.endpoint.as_str())?;
    let subscriptions = match convertir_to_bson(transaction_mappee) {
        Ok(s) => s,
        Err(e) => Err(format!("transactions.sauvegarder_subscription_webpush Erreur conversion subscription webpush {:?}", e))?
    };
    let ops = doc! {
        "$set": {
            CHAMP_NOTIFICATIONS_ACTIVES: true,
            format!("{}.{}", CHAMP_WEBPUSH_SUBSCRIPTIONS, cle_endpoint): subscriptions,
        },
        // "$addToSet": addtoset_ops,
        "$currentDate": {CHAMP_MODIFICATION: true},
    };

    let collection = middleware.get_collection(NOM_COLLECTION_PROFILS)?;
    match collection.update_one(filtre, ops, None).await {
        Ok(_d) => (),
        Err(e) => Err(format!("transactions.sauvegarder_subscription_webpush Erreur sauvegarde endpoint web push : {:?}", e))?
    }

    middleware.reponse_ok()
}

async fn retirer_subscription_webpush<M, T>(gestionnaire: &GestionnaireMessagerie, middleware: &M, transaction: T)
    -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao + ValidateurX509,
        T: Transaction
{
    debug!("retirer_subscription_webpush Consommer transaction : {:?}", &transaction);
    let transaction_mappee = match transaction.clone().convertir::<TransactionRetirerSubscriptionWebpush>() {
        Ok(t) => t,
        Err(e) => Err(format!("transactions.retirer_subscription_webpush Erreur conversion transaction : {:?}", e))?
    };

    let user_id = match &transaction.get_enveloppe_certificat() {
        Some(c) => match c.get_user_id()? {
            Some(u) => u.to_owned(),
            None => match c.verifier_roles(vec![RolesCertificats::Postmaster]) {
                true => match transaction_mappee.user_id.as_ref() {
                    Some(inner) => inner.to_owned(),
                    None => Err(format!("transactions.retirer_subscription_webpush Aucun user_id fourni par postmaster"))?
                },
                false => Err(format!("transactions.retirer_subscription_webpush Certificat sans user_id ou role != postmaster"))?
            }
        },
        None => Err(format!("Certificat sans user_id"))?
    };

    let filtre = doc!{ CHAMP_USER_ID: &user_id };

    let cle_endpoint = url_to_mongokey(transaction_mappee.endpoint.as_str())?;

    let unset_ops = doc!{
        format!("{}.{}", CHAMP_WEBPUSH_SUBSCRIPTIONS, cle_endpoint): true,
    };

    let ops = doc! {
        "$unset": unset_ops,
        "$currentDate": {CHAMP_MODIFICATION: true},
    };

    let collection = middleware.get_collection(NOM_COLLECTION_PROFILS)?;
    match collection.update_one(filtre, ops, None).await {
        Ok(_d) => (),
        Err(e) => Err(format!("transactions.retirer_subscription_webpush Erreur retrait endpoint web push : {:?}", e))?
    }

    verifier_toggle_notifications_actives(middleware, user_id.as_str()).await?;

    middleware.reponse_ok()
}

/// Toggle notifications a OFF s'il ne reste aucun web_push et email_actif est false
async fn verifier_toggle_notifications_actives<M>(middleware: &M, user_id: &str) -> Result<(), String>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    let filtre = doc!{ CHAMP_USER_ID: user_id };
    let collection = middleware.get_collection(NOM_COLLECTION_PROFILS)?;
    let doc_profil: ProfilUsagerNotifications = match collection.find_one(filtre.clone(), None).await {
        Ok(d) => match d {
            Some(d) => match convertir_bson_deserializable(d) {
                Ok(d) => d,
                Err(e) => Err(format!("transactions.verifier_toggle_notifications_actives Erreur conversion profil : {}", user_id))?
            },
            None => Err(format!("transactions.verifier_toggle_notifications_actives Aucun profil correspondant : {}", user_id))?
        },
        Err(e) => Err(format!("transactions.verifier_toggle_notifications_actives Erreur chargement profil : {:?}", e))?
    };

    let email_actif = match doc_profil.email_actif {
        Some(b) => b,
        None => false
    };

    let webpush_actif = match doc_profil.webpush_endpoints {
        Some(w) => w.len() > 0,
        None => false
    };

    let ops = doc! {
        "$set": {CHAMP_NOTIFICATIONS_ACTIVES: email_actif || webpush_actif},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };

    match collection.update_one(filtre, ops, None).await {
        Ok(r) => Ok(()),
        Err(e) => Err(format!("transactions.verifier_toggle_notifications_actives Erreur toggle notifications actives {:?}", e))?
    }
}
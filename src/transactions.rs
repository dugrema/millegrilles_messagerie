use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::convert::TryInto;

use log::{debug, info, error, warn};
use millegrilles_common_rust::{chrono, serde_json, serde_json::json};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::{bson, bson::{doc, Document}};
use millegrilles_common_rust::bson::{Array, Bson};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::constantes::Securite::{L2Prive, L4Secure};
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, Entete, MessageMilleGrille, MessageSerialise};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::middleware::{map_msg_to_bson, map_serializable_to_bson, sauvegarder_transaction_recue};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, MongoDao, verifier_erreur_duplication_mongo};
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, FindOptions, ReturnDocument, UpdateOptions};
use millegrilles_common_rust::recepteur_messages::{MessageValideAction, TypeMessage};
use millegrilles_common_rust::redis::ToRedisArgs;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::{Map, Value};
use millegrilles_common_rust::transactions::Transaction;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::verificateur::ValidationOptions;

use crate::constantes::*;
use crate::gestionnaire::GestionnaireMessagerie;
use crate::message_structs::*;
use crate::pompe_messages::{emettre_evenement_pompe, marquer_outgoing_resultat, PompeMessages};

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
        TRANSACTION_LU |
        TRANSACTION_TRANSFERT_COMPLETE |
        TRANSACTION_SUPPRIMER_MESSAGES |
        TRANSACTION_SUPPRIMER_CONTACTS => {
            match m.verifier_exchanges(vec![Securite::L4Secure]) {
                true => Ok(()),
                false => Err(format!("transactions.consommer_transaction: Message autorisation invalide (pas 4.secure)"))
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
        TRANSACTION_TRANSFERT_COMPLETE => transfert_complete(gestionnaire, middleware, transaction).await,
        TRANSACTION_SUPPRIMER_MESSAGES => supprimer_message(gestionnaire, middleware, transaction).await,
        TRANSACTION_SUPPRIMER_CONTACTS => supprimer_contacts(gestionnaire, middleware, transaction).await,
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
    let estampille = transaction.get_estampille();
    let user_id = match transaction.get_enveloppe_certificat() {
        Some(e) => e.get_user_id()?.to_owned(),
        None => None
    };

    let transaction_poster: CommandePoster = match transaction.clone().convertir::<CommandePoster>() {
        Ok(t) => t,
        Err(e) => Err(format!("messagerie.transaction_poster Erreur conversion transaction : {:?}", e))?
    };

    let uuid_message = match &transaction_poster.message.entete {
        Some(e) => Ok(e.uuid_transaction.clone()),
        None => Err(format!("transactions.transaction_poster Entete manquante du message {}", uuid_transaction))
    }?;

    // Conserver document dans outgoing et flags dans outgoing_processing
    let mut doc_bson_transaction = match convertir_to_bson(&transaction_poster) {
        Ok(d) => d,
        Err(e) => Err(format!("transactions.transaction_poster Erreur conversion transaction en bson : {:?}", e))?
    };
    let mut doc_outgoing = match doc_bson_transaction.get_document("message") {
        Ok(m) => m.to_owned(),
        Err(e) => Err(format!("transactions.transaction_poster Erreur conversion message en doc_bson : {:?}", e))?
    };
    doc_outgoing.insert("uuid_transaction", &uuid_message);
    doc_outgoing.insert("user_id", &user_id);
    doc_outgoing.insert("supprime", false);
    doc_outgoing.insert(CHAMP_DATE_ENVOI, DateEpochSeconds::from(estampille.to_owned()));

    // Ajouter map destinataires
    let mut map_destinataires = Map::new();
    for dest in &transaction_poster.get_destinataires() {
        map_destinataires.insert(dest.to_owned(), Value::from(0));
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
        TRANSACTION_CHAMP_UUID_TRANSACTION: uuid_transaction,
        CHAMP_UUID_MESSAGE: uuid_message,
        "destinataires": destinataires,
        "user_id": user_id,
        "dns_unresolved": &dns_adresses,
        "idmgs_mapping": doc!{},
        "idmgs_unprocessed": Vec::<String>::new(),
        "attachments": &transaction_poster.message.attachments,
        "created": chrono::Utc::now(),
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

    middleware.reponse_ok()
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
            let contenu: ReponseTopologieResolveIdmg = r.message.parsed.map_contenu(None)?;
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
        M: GenerateurMessages + MongoDao + ValidateurX509,
        T: Transaction
{
    debug!("transaction_recevoir Consommer transaction : {:?}", &transaction);
    let uuid_transaction = transaction.get_uuid_transaction().to_owned();
    // let certificat_millegrille_pem = match transaction.get_enveloppe_certificat() {
    //     Some(c) => c.get_pem_ca()?,
    //     None => None
    // };
    // debug!("transaction_recevoir transaction contenu {:?}", transaction.get_contenu());
    // let certificat_millegrille_pem = match transaction.
    //     get_contenu().get_str("_millegrille") {
    //     Ok(c) => Some(c.to_owned()),
    //     Err(e) => None
    // };
    // debug!("transaction_recevoir Certificat millegrille {:?}", certificat_millegrille_pem);

    // let transaction_recevoir: TransactionRecevoir = match transaction.clone().convertir::<TransactionRecevoir>() {
    //     Ok(t) => t,
    //     Err(e) => Err(format!("transaction_recevoir Erreur conversion transaction : {:?}", e))?
    // };
    let message_recevoir: CommandeRecevoirPost = match transaction.clone().convertir::<CommandeRecevoirPost>() {
        Ok(t) => t,
        Err(e) => Err(format!("transaction_recevoir Erreur conversion transaction : {:?}", e))?
    };
    let mut message_recevoir_serialise = match MessageSerialise::from_serializable(message_recevoir.message) {
        Ok(m) => Ok(m),
        Err(e) => Err(format!("transactions.transaction_recevoir Erreur mapping message serialise : {:?}", e))
    }?;

    // Valider message qui est potentiellement d'une millegrille tierce
    let message_enveloppe: DocumentMessage = match message_recevoir_serialise.parsed.map_contenu(None) {
        Ok(m) => Ok(m),
        Err(e) => Err(format!("transactions.transaction_recevoir Erreur durant conversion message vers TransactionPoster : {:?}", e))
    }?;
    let idmg_local = middleware.get_enveloppe_privee().idmg()?;
    let idmg_message = message_recevoir_serialise.get_entete().idmg.as_str();
    let uuid_message = message_recevoir_serialise.get_entete().uuid_transaction.clone();
    let certificat_millegrille_pem = message_recevoir_serialise.parsed.millegrille.clone();

    let message_local = idmg_local.as_str() == idmg_message;
    match message_local {
        true => {
            // Marquer le message comme traiter dans "outgoing local"
            let destinataires = message_recevoir.destinataires.clone();
            marquer_outgoing_resultat(
                middleware,
                uuid_message.as_str(),
                idmg_local.as_str(),
                &destinataires,
                true,
                201
            ).await?;

            let options_validation = ValidationOptions::new(false, true, true);
            let resultat_validation = match message_recevoir_serialise.valider(middleware, Some(&options_validation)).await {
                Ok(r) => Ok(r),
                Err(e) => Err(format!("transactions.transaction_recevoir Erreur durant la validation du message : {:?}", e))
            }?;
            if ! resultat_validation.valide() {
                Err(format!("Erreur validation message : {:?}", resultat_validation))?;
            }
        },
        false => {
            let options_validation = ValidationOptions::new(true, true, true);
            let resultat_validation = match message_recevoir_serialise.valider(middleware, Some(&options_validation)).await {
                Ok(r) => Ok(r),
                Err(e) => Err(format!("transactions.transaction_recevoir Erreur durant la validation du message : {:?}", e))
            }?;
            if ! resultat_validation.valide() {
                Err(format!("Erreur validation message : {:?}", resultat_validation))?;
            }
        }
    }

    // Conserver message pour chaque destinataires locaux
    //let transaction_poster: TransactionPoster = message_recevoir_serialise
    let message_chiffre = message_enveloppe.message_chiffre;
    let hachage_bytes = message_enveloppe.hachage_bytes;
    let fingerprint_usager = message_enveloppe.fingerprint_certificat;
    let attachments = message_enveloppe.attachments;

    // Retirer la part serveur du destinataire
    let destinataires = {
        let mut destinataires = Vec::new();
        for adresse in &message_recevoir.destinataires {
            match AdresseMessagerie::new(adresse.as_str()) {
                Ok(a) => destinataires.push(a.user),
                Err(e) => info!("Erreur parsing adresse {}, on l'ignore", adresse)
            }
        }

        destinataires
    };

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

    let attachments_recus = match attachments.as_ref() {
        // Si on a des attachments et le message est local : true.
        // Sinon aucuns attachments => true, au moins 1 => false
        Some(a) => message_local || a.is_empty(),
        None => true
    };

    let attachments_bson = match attachments.as_ref() {
        Some(a) => {
            let mut attachments_bson = doc!{};
            for fuuid in a {
                // Si message local, on marque recu. Sinon on met false.
                attachments_bson.insert(fuuid.to_owned(), message_local);
            }
            Some(attachments_bson)
        },
        None => None
    };

    for (nom_usager, user_id) in &reponse_mappee.usagers {
        let now: Bson = DateEpochSeconds::now().into();
        match user_id {
            Some(u) => {
                // Sauvegarder message pour l'usager
                debug!("transaction_recevoir Sauvegarder message pour usager : {}", u);
                let mut doc_user_reception = doc! {
                    "user_id": u,
                    "uuid_transaction": &uuid_transaction,
                    "uuid_message": &uuid_message,
                    "lu": false,
                    CHAMP_SUPPRIME: false,
                    "date_reception": now,
                    "date_ouverture": None::<&str>,
                    "certificat_message": &certificat_usager_pem,
                    "message_chiffre": &message_chiffre,
                    "hachage_bytes": &hachage_bytes,
                    CHAMP_ATTACHMENTS: &attachments_bson,
                    CHAMP_ATTACHMENTS_TRAITES: &attachments_recus,
                };

                if let Some(cm) = certificat_millegrille_pem.as_ref() {
                    doc_user_reception.insert("certificat_millegrille", cm);
                }

                debug!("transaction_recevoir Inserer message {:?}", doc_user_reception);
                if let Err(e) = collection.insert_one(&doc_user_reception, None).await {
                    let erreur_duplication = verifier_erreur_duplication_mongo(&*e.kind);
                    if erreur_duplication {
                        warn!("transaction_recevoir Duplication message externe recu, on l'ignore : {:?}", doc_user_reception);
                        return middleware.reponse_ok();
                    } else {
                        Err(format!("transactions.transaction_recevoir Erreur insertion message {} pour usager {} : {:?}", uuid_transaction, u, e))?
                    }
                }

                // Evenement de nouveau message pour front-end
                if let Ok(m) = convertir_bson_deserializable::<MessageIncoming>(doc_user_reception) {
                    // let message_mappe: MessageIncoming =
                    let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_NOUVEAU_MESSAGE)
                        .exchanges(vec![L2Prive])
                        .partition(u)
                        .build();
                    middleware.emettre_evenement(routage, &m).await?;
                }
            },
            None => warn!("transaction_recevoir Nom usager local inconnu : {}", nom_usager)
        }
    }

    if ! attachments_recus {
        if let Some(a) = attachments.as_ref() {
            debug!("transaction_recevoir Emettre une verification aupres de fichiers pour existance de {:?}", attachments);
            let commande = CommandeVerifierExistanceFuuidsMessage { uuid_message: uuid_message.clone(), fuuids: a.to_owned() };
            let routage = RoutageMessageAction::builder(DOMAINE_NOM, "fuuidVerifierExistance")
                .exchanges(vec![L4Secure])
                .build();
            middleware.transmettre_commande(routage, &commande, false).await?;
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
    let filtre = doc! {CHAMP_USER_ID: user_id, TRANSACTION_CHAMP_UUID_TRANSACTION: &uuid_message};
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

    // Emettre evenement lu
    {
        let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_MESSAGE_LU)
            .exchanges(vec![L2Prive])
            .partition(user_id)
            .build();
        let evenement_lu = json!({
            "lus": {&uuid_message: flag_lu},
        });
        middleware.emettre_evenement(routage, &evenement_lu).await?;
    }

    middleware.reponse_ok()
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
    if let Err(e) = collection.update_one(filtre, ops, None).await {
        Err(format!("transactions.transfert_complete Erreur update pour transfert complete {} : {:?}", uuid_message, e))?;
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
    let filtre = doc! {CHAMP_USER_ID: &user_id, TRANSACTION_CHAMP_UUID_TRANSACTION: {"$in": &uuid_transactions}};
    let ops = doc! {
        "$set": { CHAMP_SUPPRIME: true },
        "$currentDate": {CHAMP_MODIFICATION: true},
    };

    debug!("supprimer_message filtre : {:?}, ops: {:?}", filtre, ops);

    let collection = middleware.get_collection(NOM_COLLECTION_INCOMING)?;
    match collection.update_many(filtre, ops, None).await {
        Ok(r) => debug!("supprimer_message Resultat : {:?}", r),
        Err(e) => Err(format!("transactions.supprimer_message Erreur update pour transfert complete {} : {:?}", uuid_transaction, e))?
    }

    let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_MESSAGES_SUPPRIMES)
        .exchanges(vec![L2Prive])
        .partition(&user_id)
        .build();
    let evenement_supprime = json!({
        "uuid_transactions": &uuid_transactions,
    });
    middleware.emettre_evenement(routage, &evenement_supprime).await?;

    middleware.reponse_ok()
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

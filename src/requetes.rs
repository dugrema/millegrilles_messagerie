use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::convert::{TryFrom, TryInto};
use std::ops::Deref;

use log::{debug, error, warn};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{Bson, doc, Document};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chiffrage_cle::ReponseDechiffrageCles;
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::middleware::sauvegarder_traiter_transaction;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, filtrer_doc_id, MongoDao};
use millegrilles_common_rust::mongodb::Cursor;
use millegrilles_common_rust::mongodb::options::{FindOneOptions, FindOptions, Hint, UpdateOptions};
use millegrilles_common_rust::recepteur_messages::{MessageValideAction, TypeMessage};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::Transaction;
use millegrilles_common_rust::verificateur::VerificateurMessage;

use crate::gestionnaire::GestionnaireMessagerie;
use crate::constantes::*;
use crate::transactions::*;
use crate::message_structs::*;

const REQUETE_DECHIFFRAGE: &str = "dechiffrage";

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
                REQUETE_GET_MESSAGES => requete_get_messages(middleware, message, gestionnaire).await,
                REQUETE_GET_REFERENCE_MESSAGES => requete_get_reference_messages(middleware, message, gestionnaire).await,
                REQUETE_GET_PERMISSION_MESSAGES => requete_get_permission_messages(middleware, message).await,
                REQUETE_GET_PROFIL => requete_get_profil(middleware, message).await,
                REQUETE_GET_CONTACTS => requete_get_contacts(middleware, message).await,
                REQUETE_GET_REFERENCE_CONTACTS => requete_get_reference_contacts(middleware, message).await,
                REQUETE_ATTACHMENT_REQUIS => requete_attachment_requis(middleware, message).await,
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

async fn requete_get_messages<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_get_messages Message : {:?}", & m.message);
    let requete: RequeteGetMessages = m.message.get_msg().map_contenu(None)?;
    debug!("requete_get_messages parsed : {:?}", requete);

    let user_id = match m.get_user_id() {
        Some(u) => u,
        None => return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "msg": "Access denied"}), None)?))
    };

    let limit = match requete.limit {
        Some(l) => l,
        None => 100
    };
    let skip = match requete.skip {
        Some(s) => s,
        None => 0
    };

    let inclure_supprime = match requete.inclure_supprime { Some(b) => b, None => false };
    let messages_envoyes = match requete.messages_envoyes { Some(b) => b, None => false };

    let champ_date = match messages_envoyes {
        true => CHAMP_DATE_ENVOI,
        false => CHAMP_DATE_RECEPTION
    };

    let nom_collection = match messages_envoyes {
        true => NOM_COLLECTION_OUTGOING,
        false => NOM_COLLECTION_INCOMING,
    };

    let opts = FindOptions::builder()
        // .hint(Hint::Name(String::from("fichiers_activite_recente")))
        .sort(doc!{champ_date: -1})
        .limit(limit)
        .skip(skip)
        .build();
    let mut filtre = doc!{CHAMP_USER_ID: user_id};
    if ! inclure_supprime {
        filtre.insert(CHAMP_SUPPRIME, false);
    }

    if let Some(um) = requete.uuid_messages {
        filtre.insert("uuid_transaction", doc!{"$in": um});
    }

    let collection = middleware.get_collection(nom_collection)?;
    let mut curseur = collection.find(filtre, opts).await?;
    let fichiers_mappes = mapper_messages_curseur(curseur, messages_envoyes).await?;

    let reponse = json!({ "messages": fichiers_mappes });
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

async fn requete_get_reference_messages<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_get_reference_messages Message : {:?}", & m.message);
    let requete: RequeteGetReferenceMessages = m.message.get_msg().map_contenu(None)?;
    debug!("requete_get_reference_messages cle parsed : {:?}", requete);

    let user_id = match m.get_user_id() {
        Some(u) => u,
        None => return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "msg": "Access denied"}), None)?))
    };

    let limit = match requete.limit {
        Some(l) => l,
        None => 1000
    };

    let inclure_supprime = match requete.inclure_supprime { Some(b) => b, None => false };
    let messages_envoyes = match requete.messages_envoyes { Some(b) => b, None => false };

    let champ_date = match messages_envoyes {
        true => CHAMP_DATE_ENVOI,
        false => CHAMP_DATE_RECEPTION
    };

    let nom_collection = match messages_envoyes {
        true => NOM_COLLECTION_OUTGOING,
        false => NOM_COLLECTION_INCOMING,
    };

    let opts = FindOptions::builder()
        .sort(doc!{champ_date: 1})
        .limit(limit)
        .build();
    let mut filtre = doc!{CHAMP_USER_ID: user_id};
    if ! inclure_supprime {
        filtre.insert(CHAMP_SUPPRIME, false);
    }
    if let Some(d) = requete.date_minimum.as_ref() {
        filtre.insert(champ_date, doc!{"$gte": d});
    }

    debug!("requete_get_reference_messages Filter messages collection {} : {:?}", nom_collection, filtre);

    let collection = middleware.get_collection(nom_collection)?;
    let mut curseur = collection.find(filtre, opts).await?;
    let fichiers_mappes = mapper_reference_messages_curseur(curseur).await?;

    let reponse = json!({ "messages": fichiers_mappes });
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

async fn mapper_messages_curseur(mut curseur: Cursor<Document>, type_envoi: bool) -> Result<Value, Box<dyn Error>> {

    let messages_value = match type_envoi {
        true => {
            let mut messages_mappes = Vec::new();
            while let Some(fresult) = curseur.next().await {
                let fcurseur = fresult?;
                let message_db: MessageOutgoing = convertir_bson_deserializable(fcurseur)?;
                messages_mappes.push(message_db);
            }
            // Convertir fichiers en Value (serde pour reponse json)
            serde_json::to_value(messages_mappes)
        },
        false => {
            let mut messages_mappes = Vec::new();
            while let Some(fresult) = curseur.next().await {
                let fcurseur = fresult?;
                let message_db: MessageIncoming = convertir_bson_deserializable(fcurseur)?;
                messages_mappes.push(message_db);
            }
            // Convertir fichiers en Value (serde pour reponse json)
            serde_json::to_value(messages_mappes)
        }
    }?;

    Ok(messages_value)
}

async fn mapper_reference_messages_curseur(mut curseur: Cursor<Document>) -> Result<Value, Box<dyn Error>> {
    let mut messages_mappes = Vec::new();

    while let Some(fresult) = curseur.next().await {
        let fcurseur = fresult?;
        let mut message_db: MessageIncomingReference = convertir_bson_deserializable(fcurseur)?;
        messages_mappes.push(message_db);
    }

    // Convertir fichiers en Value (serde pour reponse json)
    Ok(serde_json::to_value(messages_mappes)?)
}

// #[derive(Clone, Debug, Serialize, Deserialize)]
// struct RequetePlusRecente {
//     limit: Option<i64>,
//     skip: Option<u64>,
// }

pub fn mapper_message_db(fichier: Document) -> Result<MessageIncoming, Box<dyn Error>> {
    let mut message_mappe: MessageIncoming = convertir_bson_deserializable(fichier)?;
    debug!("Message mappe : {:?}", message_mappe);
    Ok(message_mappe)
}

async fn requete_get_permission_messages<M>(middleware: &M, m: MessageValideAction)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    let user_id = match m.get_user_id() {
        Some(u) => u,
        None => return Ok(Some(middleware.formatter_reponse(json!({"err": true, "message": "user_id n'est pas dans le certificat"}), None)?))
    };

    debug!("requete_get_permission Message : {:?}", & m.message);
    let requete: ParametresGetPermissionMessages = m.message.get_msg().map_contenu(None)?;
    debug!("requete_get_permission parsed : {:?}", requete);

    let messages_envoyes = match requete.messages_envoyes { Some(b) => b, None => false };

    let nom_collection = match messages_envoyes {
        true => NOM_COLLECTION_OUTGOING,
        false => NOM_COLLECTION_INCOMING,
    };

    // Utiliser certificat du message client (requete) pour demande de rechiffrage
    let pem_rechiffrage: Vec<String> = match &m.message.certificat {
        Some(c) => {
            let fp_certs = c.get_pem_vec();
            fp_certs.into_iter().map(|cert| cert.pem).collect()
        },
        None => Err(format!(""))?
    };

    let mut filtre = doc!{
        "user_id": &user_id,
        "uuid_transaction": {"$in": &requete.uuid_transaction_messages},
    };
    let mut projection = doc! {
        "uuid_transaction": true,
        "hachage_bytes": true,
    };
    let opts = FindOptions::builder().projection(projection).limit(1000).build();
    let collection = middleware.get_collection(nom_collection)?;
    let mut curseur = collection.find(filtre, Some(opts)).await?;

    let mut hachage_bytes = HashSet::new();
    while let Some(fresult) = curseur.next().await {
        let doc_result = fresult?;
        match messages_envoyes {
            true => {
                let doc_message_outgoing: MessageOutgoingProjectionPermission = convertir_bson_deserializable(doc_result)?;
                hachage_bytes.insert(doc_message_outgoing.hachage_bytes);

                if let Some(attachments) = &doc_message_outgoing.attachments {
                    for h in attachments {
                        hachage_bytes.insert(h.to_owned());
                    }
                }

            },
            false => {
                let doc_message_incoming: MessageIncomingProjectionPermission = convertir_bson_deserializable(doc_result)?;
                hachage_bytes.insert(doc_message_incoming.hachage_bytes);

                if let Some(attachments) = &doc_message_incoming.attachments {
                    for (h, _) in attachments {
                        hachage_bytes.insert(h.to_owned());
                    }
                }
            }
        }
    }

    if hachage_bytes.len() == 0 {
        debug!("Aucun message identifie a partir de la liste {:?}", hachage_bytes);
        return Ok(Some(middleware.formatter_reponse(&json!({"ok": true, "message": "Aucun message correspondant trouve"}), None)?));
    }

    let permission = json!({
        "liste_hachage_bytes": hachage_bytes,
        "certificat_rechiffrage": pem_rechiffrage,
    });

    // Emettre requete de rechiffrage de cle, reponse acheminee directement au demandeur
    let reply_to = match m.reply_q {
        Some(r) => r,
        None => Err(format!("requetes.requete_get_permission Pas de reply q pour message"))?
    };
    let correlation_id = match m.correlation_id {
        Some(r) => r,
        None => Err(format!("requetes.requete_get_permission Pas de correlation_id pour message"))?
    };
    let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, REQUETE_DECHIFFRAGE)
        .exchanges(vec![Securite::L2Prive])
        .reply_to(reply_to)
        .correlation_id(correlation_id)
        .blocking(false)
        .build();

    middleware.transmettre_requete(routage, &permission).await?;

    Ok(None)
}

async fn requete_get_profil<M>(middleware: &M, m: MessageValideAction)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    let user_id = match m.get_user_id() {
        Some(u) => u,
        None => return Ok(Some(middleware.formatter_reponse(json!({"err": true, "code": 403, "message": "user_id n'est pas dans le certificat"}), None)?))
    };

    debug!("requete_get_profil Message : {:?}", & m.message);
    let requete: ParametresGetProfil = m.message.get_msg().map_contenu(None)?;
    debug!("requete_get_profil cle parsed : {:?}", requete);

    let pem_cert = match m.message.certificat {
        Some(c) => {
            Some(c.get_pem_vec().iter().map(|c|c.pem.clone()).collect::<Vec<String>>())
        },
        None => None
    };

    let collection = middleware.get_collection(NOM_COLLECTION_PROFILS)?;
    let filtre = doc! {CHAMP_USER_ID: user_id};
    let reponse = match collection.find_one(filtre, None).await? {
        Some(mut d) => {
            let mut profil_reponse: ProfilReponse = convertir_bson_deserializable(d)?;

            // Charger la cle du profil
            if let Some(pem) = pem_cert {
                let routage = RoutageMessageAction::builder(
                    DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE)
                    .exchanges(vec![Securite::L4Secure])
                    .build();
                let requete_cle = json!({
                    "liste_hachage_bytes": [profil_reponse.cle_ref_hachage_bytes.as_str()],
                    "certificat_rechiffrage": pem,
                });
                debug!("requete_get_profil Requete cle : {:?}", requete_cle);
                if let TypeMessage::Valide(reponse_cle) = middleware.transmettre_requete(routage, &requete_cle).await? {
                    debug!("requete_get_profil Reponse cle : {:?}", reponse_cle);
                    let cles: ReponseDechiffrageCles = reponse_cle.message.get_msg().map_contenu(None)?;
                    profil_reponse.cles = Some(cles);
                } else {
                    warn!("requete_get_profil Reponse cle mauvais type (!Valide)");
                }
            }

            middleware.formatter_reponse(profil_reponse, None)
        },
        None => {
            let reponse_profil_introuvable = json!({"ok": false, "code": 404});
            middleware.formatter_reponse(reponse_profil_introuvable, None)
        }
    }?;

    debug!("get_profil Reponse {:?}", reponse);

    Ok(Some(reponse))
}

async fn requete_get_contacts<M>(middleware: &M, m: MessageValideAction)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    let user_id = match m.get_user_id() {
        Some(u) => u,
        None => return Ok(Some(middleware.formatter_reponse(json!({"err": true, "code": 403, "message": "user_id n'est pas dans le certificat"}), None)?))
    };

    debug!("requete_get_contacts Message : {:?}", & m.message);
    let requete: ParametresGetContacts = m.message.get_msg().map_contenu(None)?;
    debug!("requete_get_contacts cle parsed : {:?}", requete);

    let contacts = {
        let mut contacts = Vec::new();

        let sort_key = match requete.sort_key {
            Some(s) => s,
            None => SortKey { colonne: CHAMP_CREATION.into(), ordre: None }
        };
        let ordre = match sort_key.ordre {
            Some(o) => o,
            None => 1,
        };

        let limit = match requete.limit {
            Some(l) => l,
            None => 100
        };
        let skip = match requete.skip {
            Some(s) => s,
            None => 0
        };
        let opts = FindOptions::builder()
            .sort(doc! {sort_key.colonne: ordre, CHAMP_CREATION: 1})
            .limit(limit)
            .skip(skip)
            .build();

        let collection = middleware.get_collection(NOM_COLLECTION_CONTACTS)?;
        let mut filtre = doc! {CHAMP_USER_ID: user_id, CHAMP_SUPPRIME: false};

        if let Some(uuids_contacts) = requete.uuid_contacts.as_ref() {
            filtre.insert(CHAMP_UUID_CONTACT, doc!{"$in": uuids_contacts});
        }

        let mut curseur = collection.find(filtre, opts).await?;

        while let Some(r) = curseur.next().await {
            let contact_doc = r?;
            let date_modification = contact_doc.get_datetime(CHAMP_MODIFICATION)?.clone();

            let mut contact_mappe: Contact = convertir_bson_deserializable(contact_doc)?;
            contact_mappe.date_modification = Some(DateEpochSeconds::from(date_modification.to_chrono()));
            contacts.push(contact_mappe);
        }

        contacts
    };

    let reponse = {
        let message_reponse = json!({
            "contacts": contacts,
        });
        middleware.formatter_reponse(message_reponse, None)?
    };
    debug!("get_profil Reponse {:?}", reponse);

    Ok(Some(reponse))
}

async fn requete_get_reference_contacts<M>(middleware: &M, m: MessageValideAction)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    let user_id = match m.get_user_id() {
        Some(u) => u,
        None => return Ok(Some(middleware.formatter_reponse(json!({"err": true, "code": 403, "message": "user_id n'est pas dans le certificat"}), None)?))
    };

    debug!("requete_get_reference_contacts Message : {:?}", & m.message);
    let requete: ParametresGetContacts = m.message.get_msg().map_contenu(None)?;
    debug!("requete_get_reference_contacts cle parsed : {:?}", requete);

    let contacts = {
        let mut contacts = Vec::new();

        let limit = match requete.limit {
            Some(l) => l,
            None => 1000
        };
        let skip = match requete.skip {
            Some(s) => s,
            None => 0
        };
        let opts = FindOptions::builder()
            .sort(doc! {CHAMP_CREATION: 1})
            .limit(limit)
            .skip(skip)
            .build();

        let collection = middleware.get_collection(NOM_COLLECTION_CONTACTS)?;
        let filtre = doc! {CHAMP_USER_ID: user_id};
        let mut curseur = collection.find(filtre, opts).await?;

        while let Some(r) = curseur.next().await {
            let contact_doc = r?;
            let date_modification = contact_doc.get_datetime(CHAMP_MODIFICATION)?.clone();

            let mut contact_mappe: ReferenceContact = convertir_bson_deserializable(contact_doc)?;
            contact_mappe.date_modification = Some(DateEpochSeconds::from(date_modification.to_chrono()));

            contacts.push(contact_mappe);
        }

        contacts
    };

    let reponse = {
        let message_reponse = json!({
            "contacts": contacts,
        });
        middleware.formatter_reponse(message_reponse, None)?
    };
    debug!("requete_get_reference_contacts Reponse {:?}", reponse);

    Ok(Some(reponse))
}

async fn requete_attachment_requis<M>(middleware: &M, m: MessageValideAction)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_attachment_requis Message : {:?}", & m.message);
    let requete: ParametresRequeteAttachmentRequis = m.message.get_msg().map_contenu(None)?;
    debug!("requete_attachment_requis parsed : {:?}", requete);

    let collection = middleware.get_collection(NOM_COLLECTION_INCOMING)?;
    let options = FindOneOptions::builder().projection(doc!{"_id": true}).build();

    let mut reponse_fuuid: HashMap<String, bool> = HashMap::new();
    for fuuid in &requete.fuuids {
        let filtre = doc! {
            CHAMP_ATTACHMENTS_TRAITES: false,
            format!("attachments.{}", fuuid): false,
        };
        let resultat = collection.find_one(filtre.clone(), Some(options.clone())).await?;
        reponse_fuuid.insert(fuuid.into(), resultat.is_some());
    }

    let reponse = ReponseRequeteAttachmentRequis {
        fuuids: reponse_fuuid,
    };

    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

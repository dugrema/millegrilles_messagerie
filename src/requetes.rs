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
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
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
                REQUETE_GET_PERMISSION_MESSAGES => requete_get_permission_messages(middleware, message).await,
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
    debug!("requete_get_messages cle parsed : {:?}", requete);

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

    let opts = FindOptions::builder()
        // .hint(Hint::Name(String::from("fichiers_activite_recente")))
        .sort(doc!{CHAMP_DATE_RECEPTION: -1})
        .limit(limit)
        .skip(skip)
        .build();
    let mut filtre = doc!{CHAMP_SUPPRIME: false, CHAMP_USER_ID: user_id};

    if let Some(um) = requete.uuid_messages {
        filtre.insert("uuid_transaction", doc!{"$in": um});
    }

    let collection = middleware.get_collection(NOM_COLLECTION_INCOMING)?;
    let mut curseur = collection.find(filtre, opts).await?;
    let fichiers_mappes = mapper_messages_curseur(curseur).await?;

    let reponse = json!({ "messages": fichiers_mappes });
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

async fn mapper_messages_curseur(mut curseur: Cursor<Document>) -> Result<Value, Box<dyn Error>> {
    let mut messages_mappes = Vec::new();

    while let Some(fresult) = curseur.next().await {
        let fcurseur = fresult?;
        let message_db = mapper_message_db(fcurseur)?;
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
    debug!("requete_get_permission cle parsed : {:?}", requete);

    // Utiliser certificat du message client (requete) pour demande de rechiffrage
    let pem_rechiffrage: Vec<String> = match m.message.certificat {
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
    let projection = doc! {"uuid_transaction": true, "attachments": true, "hachage_bytes": true};
    let opts = FindOptions::builder().projection(projection).limit(1000).build();
    let collection = middleware.get_collection(NOM_COLLECTION_INCOMING)?;
    let mut curseur = collection.find(filtre, Some(opts)).await?;

    let mut hachage_bytes = HashSet::new();
    while let Some(fresult) = curseur.next().await {
        let doc_result = fresult?;
        let doc_message_incoming: MessageIncomingProjectionPermission = convertir_bson_deserializable(doc_result)?;
        hachage_bytes.insert(doc_message_incoming.hachage_bytes);

        if let Some(attachments) = &doc_message_incoming.attachments {
            for h in attachments {
                hachage_bytes.insert(h.to_owned());
            }
        }
    }

    // let permission = json!({
    //     "permission_hachage_bytes": hachage_bytes,
    //     "permission_duree": 300,
    // });

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

    Ok(Some(middleware.formatter_reponse(&permission, None)?))
}
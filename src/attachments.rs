use std::collections::HashSet;
use std::error::Error;
use log::{debug, error, warn};

use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::constantes::Securite::L2Prive;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::recepteur_messages::TypeMessage;
use millegrilles_common_rust::serde_json::json;

use crate::constantes::*;

use crate::gestionnaire::GestionnaireMessagerie;
use crate::message_structs::{MessageIncomingProjectionAttachments, ReponseVerifierExistanceFuuidsMessage};

pub async fn entretien_attachments<M>(middleware: &M) -> Result<(), Box<dyn Error>>
    where M: MongoDao + GenerateurMessages
{
    debug!("Debut entretien_attachments");

    let fuuids_manquants = marquer_attachments_fichiers(middleware).await?;
    verification_attachments(middleware, fuuids_manquants).await?;
    marquer_attachments_expires(middleware).await?;

    debug!("Fin entretien attachments");
    Ok(())
}

pub async fn marquer_attachments_fichiers<M>(middleware: &M) -> Result<Vec<String>, Box<dyn Error>>
    where M: MongoDao + GenerateurMessages
{
    debug!("Debut requete_attachments_fichiers");
    let mut attachments_manquants = HashSet::new();

    {
        let filtre = doc! { CHAMP_ATTACHMENTS_TRAITES: false };
        let collection = middleware.get_collection(NOM_COLLECTION_INCOMING)?;

        {
            // Marquer message comme visites
            let ops = doc!{
                "$inc": {"attachments_retry": 1},
                "$currentDate": {CHAMP_MODIFICATION: true},
            };
            collection.update_many(filtre.clone(), ops, None).await?;
        }

        let mut curseur = collection.find(filtre, None).await?;
        while let Some(d) = curseur.next().await {
            let docres = d?;
            let message: MessageIncomingProjectionAttachments = convertir_bson_deserializable(docres)?;

            let mut attachments_traites = true;
            if let Some(a) = message.attachments {
                for (k, traite) in a {
                    if ! traite {
                        // Flag pour indiquer que le
                        attachments_traites = false;
                        attachments_manquants.insert(k);
                    }
                }
            }

            if attachments_traites {
                // Flag message (transaction) comme etant complete
                let filtre_update = doc!{
                    "user_id": message.user_id,
                    "uuid_transaction": message.message_id,
                };
                let ops = doc!{
                    "$set": { CHAMP_ATTACHMENTS_TRAITES: true },
                    "$currentDate": { CHAMP_MODIFICATION: true },
                };
                collection.update_one(filtre_update, ops, None).await?;
            }
        }
    }

    Ok(Vec::from_iter(attachments_manquants.into_iter()))
}

async fn verification_attachments<M>(middleware: &M, fuuids: Vec<String>) -> Result<(), Box<dyn Error>>
    where M: MongoDao + GenerateurMessages
{
    debug!("Debut verification_attachments");
    // Faire requete vers fichiers
    let routage = RoutageMessageAction::builder("fichiers", "fuuidVerifierExistance")
        .exchanges(vec![L2Prive])
        .build();
    let requete = json!({"fuuids": &fuuids});
    let reponse = middleware.transmettre_requete(routage, &requete).await?;

    debug!("verification_attachments Reponse : {:?}", reponse);
    // let mut set_ops = doc!{};
    if let TypeMessage::Valide(r) = reponse {
        let reponse_mappee: ReponseVerifierExistanceFuuidsMessage = r.message.parsed.map_contenu()?;
        for (key, value) in reponse_mappee.fuuids.into_iter() {
            if value {
                // set_ops.insert(format!("attachments.{}", key), true);
                let filtre = doc!{
                    format!("attachments.{}", key): false,
                };
                let ops = doc!{
                    "$set": {format!("attachments.{}", key): true},
                    "$currentDate": {CHAMP_MODIFICATION: true},
                };
                let collection = middleware.get_collection(NOM_COLLECTION_INCOMING)?;
                collection.update_many(filtre, ops, None).await?;
            }
        }
    }

    Ok(())
}

async fn marquer_attachments_expires<M>(middleware: &M) -> Result<(), Box<dyn Error>>
    where M: MongoDao + GenerateurMessages
{
    debug!("Debut verification_attachments");

    let filtre = doc!{
        CHAMP_ATTACHMENTS_TRAITES: false,
        CHAMP_ATTACHMENTS_RETRY: {"$gte": 10}
    };
    let ops = doc!{
        "$set": {
            CHAMP_ATTACHMENTS_TRAITES: true,
            "attachments_code": 1,
        },
        "$currentDate": { CHAMP_MODIFICATION: true },
    };
    let collection = middleware.get_collection(NOM_COLLECTION_INCOMING)?;
    collection.update_many(filtre, ops, None).await?;

    Ok(())
}

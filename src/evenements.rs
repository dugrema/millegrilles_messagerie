use std::collections::{HashMap, HashSet};
use std::error::Error;

use log::{debug, error, info, warn};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::constantes::Securite;
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, FindOptions, Hint, ReturnDocument, UpdateOptions};
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::constantes::Securite::L2Prive;
use millegrilles_common_rust::middleware::{sauvegarder_traiter_transaction, sauvegarder_traiter_transaction_serializable};
use millegrilles_common_rust::serde::Deserialize;
use millegrilles_common_rust::verificateur::VerificateurMessage;

use crate::constantes::*;
use crate::message_structs::*;
use crate::gestionnaire::GestionnaireMessagerie;
use crate::pompe_messages::{evenement_pompe_poste, verifier_fin_transferts_attachments};

pub async fn consommer_evenement<M>(gestionnaire: &GestionnaireMessagerie, middleware: &M, m: MessageValideAction)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + VerificateurMessage
{
    debug!("gestionnaire.consommer_evenement Consommer evenement : {:?}", &m.message);

    // Autorisation selon l'action
    let niveau_securite_requis = match m.action.as_str() {
        // EVENEMENT_UPLOAD_ATTACHMENT => Ok(Securite::L1Public),
        EVENEMENT_POMPE_POSTE => Ok(Securite::L4Secure),
        EVENEMENT_FICHIERS_CONSIGNE => Ok(Securite::L2Prive),
        EVENEMENT_CONFIRMER_ETAT_FUUIDS => Ok(Securite::L2Prive),
        _ => Err(format!("gestionnaire.consommer_evenement: Action inconnue : {}", m.action.as_str())),
    }?;

    if m.verifier_exchanges(vec![niveau_securite_requis.clone()]) {
        match m.action.as_str() {
            // EVENEMENT_UPLOAD_ATTACHMENT => evenement_upload_attachment(middleware, m).await,
            EVENEMENT_POMPE_POSTE => evenement_pompe_poste(gestionnaire, middleware, &m).await,
            EVENEMENT_FICHIERS_CONSIGNE => evenement_fichier_consigne(gestionnaire, middleware, &m).await,
            EVENEMENT_CONFIRMER_ETAT_FUUIDS => evenement_confirmer_etat_fuuids(middleware, m).await,
            _ => Err(format!("gestionnaire.consommer_transaction: Mauvais type d'action pour un evenement 1.public : {}", m.action))?,
        }
    } else {
        Err(format!("gestionnaire.consommer_evenement: Niveau de securite invalide pour action {} : doit etre {:?}",
                    m.action.as_str(), niveau_securite_requis))?
    }

}

// async fn evenement_upload_attachment<M>(middleware: &M, m: MessageValideAction)
//     -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
//     where M: GenerateurMessages + MongoDao + ValidateurX509,
// {
//     debug!("evenement_upload_attachment Consommer : {:?}", & m.message);
//     let evenement: EvenementUploadAttachment = m.message.get_msg().map_contenu(None)?;
//     debug!("evenement_upload_attachment parsed : {:?}", evenement);
//
//     let idmg = evenement.idmg.as_str();
//     let uuid_message = evenement.uuid_message.as_str();
//     let fuuid = evenement.fuuid.as_str();
//     let ts_courant = Utc::now().timestamp();
//
//     let ops = match evenement.code {
//         CODE_UPLOAD_DEBUT | CODE_UPLOAD_ENCOURS => {
//             // Faire un touch
//             doc! {
//                 "$set": { format!("idmgs_mapping.{}.attachments_en_cours.{}.last_update", idmg, fuuid): ts_courant },
//                 // S'assurer que le fichier n'a pas ete remis dans la file
//                 "$pull": { format!("idmgs_mapping.{}.attachments_restants", idmg): fuuid, },
//                 "$currentDate": {CHAMP_LAST_PROCESSED: true},
//             }
//         },
//         CODE_UPLOAD_TERMINE => {
//             // Marquer fuuid comme complete
//             doc! {
//                 "$addToSet": { format!("idmgs_mapping.{}.attachments_completes", idmg): fuuid},
//                 "$unset": { format!("idmgs_mapping.{}.attachments_en_cours.{}", idmg, fuuid): true },
//                 // S'assurer que le fichier n'a pas ete remis dans la file
//                 "$pull": { format!("idmgs_mapping.{}.attachments_restants", idmg): fuuid, },
//                 "$currentDate": {CHAMP_LAST_PROCESSED: true},
//             }
//         },
//         CODE_UPLOAD_ERREUR => {
//             warn!("Remettre le fuuid a la fin de la file, ajouter next_push_time");
//             return Ok(None);
//         },
//         _ => {
//             Err(format!("evenements.evenement_upload_attachment Recu evenement inconnu (code: {}), on l'ignore", evenement.code))?
//         }
//     };
//
//     let filtre = doc! {CHAMP_UUID_MESSAGE: uuid_message};
//     let options = FindOneAndUpdateOptions::builder()
//         .return_document(ReturnDocument::After)
//         .build();
//     let collection = middleware.get_collection(NOM_COLLECTION_OUTGOING_PROCESSING)?;
//     let doc_outgoing = collection.find_one_and_update(filtre, ops, Some(options)).await?;
//     let doc_outgoing: DocOutgointProcessing = match doc_outgoing {
//         Some(d) => Ok(convertir_bson_deserializable(d)?),
//         None => {
//             Err(format!("evenements.evenement_upload_attachment Evenement recu pour doc_outgoing inconnu"))
//         }
//     }?;
//     verifier_fin_transferts_attachments(middleware, &doc_outgoing).await?;
//
//     Ok(None)
// }

#[derive(Deserialize)]
struct DocFichiersMessage {
    message: MessageIncomingReferenceSub,
    fichiers: HashMap<String, bool>
}

async fn verifier_fichiers_incoming_completes<M>(middleware: &M, gestionnaire: &GestionnaireMessagerie, message: EvenementFichiersConsigne)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509 + VerificateurMessage
{
    let collection = middleware.get_collection(NOM_COLLECTION_INCOMING)?;
    let fuuid = message.hachage_bytes.as_str();
    let filtre = doc!{
        CHAMP_FICHIERS_COMPLETES: false,
        format!("fichiers.{}", fuuid): true,
    };
    let options = FindOptions::builder()
        .hint(Hint::Name(String::from("fichiers_fuuid")))
        .projection(Some(doc!{
            "message.id": true,
            "message.estampille": true,
            "fichiers": true,
        }))
        .build();

    // Conserver messages ids - skip doublons du au meme message avec plusieurs destinataires
    let mut message_ids = HashSet::new();

    let mut curseur = collection.find(filtre, Some(options)).await?;
    while let Some(r) = curseur.next().await {
        let doc_fichiers: DocFichiersMessage = convertir_bson_deserializable(r?)?;

        if message_ids.contains(&doc_fichiers.message.id) {
            // Skip, le message est deja dans la liste (destinataire different, meme message)
            continue;
        }

        let message_id = doc_fichiers.message.id.as_str();
        message_ids.insert(message_id.to_owned());

        // Verifier si tous les fichiers sont recus (true)
        let mut tous_recus = true;

        let mut fuuids_fichiers = Vec::new();
        for (fuuid, r) in doc_fichiers.fichiers.into_iter() {
            fuuids_fichiers.push(fuuid);
            tous_recus &= r;
        }

        if tous_recus == true {
            // Tous les fichiers sont recus, creer transaction pour marquer reception completee
            let transaction = TransactionFichiersCompletes { message_id: message_id.to_owned(), fichiers: Some(fuuids_fichiers)};
            debug!("verifier_fichiers_incoming_completes Tous les fichiers sont recus pour {}", message_id);
            sauvegarder_traiter_transaction_serializable(
                middleware, &transaction, gestionnaire, DOMAINE_NOM, TRANSACTION_TRANSFERT_FICHIERS_COMPLETES).await?;
        }
    }

    Ok(None)
}

pub async fn evenement_fichier_consigne<M>(gestionnaire: &GestionnaireMessagerie, middleware: &M, m: &MessageValideAction)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + VerificateurMessage
{
    debug!("evenement_fichier_consigne Evenement recu {:?}", m);
    let tx_pompe = gestionnaire.get_tx_pompe();
    let message: EvenementFichiersConsigne = m.message.parsed.map_contenu()?;
    debug!("evenement_fichier_consigne parsed {:?}", message);

    let filtre = doc!{
        CHAMP_FICHIERS_COMPLETES: false,
        format!("fichiers.{}", message.hachage_bytes): false,
    };
    let ops = doc!{
        "$set": {
            format!("fichiers.{}", message.hachage_bytes): true,
        },
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let options = UpdateOptions::builder()
        .hint(Hint::Name(String::from("fichiers_fuuid")))
        .build();
    let collection = middleware.get_collection(NOM_COLLECTION_INCOMING)?;
    let resultat = collection.update_many(filtre, ops, Some(options)).await?;
    debug!("evenement_fichier_consigne Resultat maj {:?}", resultat);

    if resultat.modified_count > 0 {
        debug!("evenement_fichier_consigne Verifier si fichiers de {} messages sont completes", resultat.modified_count);
        Ok(verifier_fichiers_incoming_completes(middleware, gestionnaire, message).await?)
    } else {
        Ok(None)
    }
}

async fn evenement_confirmer_etat_fuuids<M>(middleware: &M, m: MessageValideAction)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao,
{
    let uuid_transaction = m.correlation_id.clone();

    if !m.verifier_exchanges(vec![L2Prive]) {
        error!("evenement_confirmer_etat_fuuids Acces refuse, certificat n'est pas d'un exchange L2 : {:?}", uuid_transaction);
        return Ok(None)
    }

    debug!("evenement_confirmer_etat_fuuids Message : {:?}", & m.message);
    let evenement: EvenementConfirmerEtatFuuids = m.message.get_msg().map_contenu()?;
    debug!("evenement_confirmer_etat_fuuids parsed : {:?}", evenement);

    repondre_fuuids(middleware, &evenement.fuuids).await?;

    Ok(None)
}

async fn repondre_fuuids<M>(middleware: &M, evenement_fuuids: &Vec<String>)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + MongoDao,
{
    let mut fuuids = HashSet::new();
    for fuuid in evenement_fuuids.iter() {
        fuuids.insert(fuuid.clone());
    }

    let opts = FindOptions::builder()
        .hint(Hint::Name(String::from("fichiers_fuuid")))
        .build();
    // let mut filtre = doc!{"fuuids": {"$in": evenement_fuuids}};
    let mut vec_fuuids = Vec::new();
    for fuuid in evenement_fuuids {
        vec_fuuids.push(doc!{format!("fichiers.{}", fuuid): true});
    }
    let filtre = doc! {
        "$or": vec_fuuids,
        "supprime": false
    };

    debug!("repondre_fuuids filtre {:?}", filtre);

    let collection = middleware.get_collection(NOM_COLLECTION_INCOMING)?;
    let mut fichiers_confirmation = Vec::new();
    let mut curseur = collection.find(filtre, opts).await?;
    while let Some(d) = curseur.next().await {
        let record: RowEtatFuuid = convertir_bson_deserializable(d?)?;
        let attachments_traites = record.fichiers_completes;
        for (fuuid, traite) in record.fichiers.into_iter() {
            if fuuids.contains(&fuuid) {
                fuuids.remove(&fuuid);
                // Note: on ignore les fichiers supprimes == true, on va laisser la chance a
                //       un autre module d'en garder possession.
                let conserver = attachments_traites == false || traite == true;
                if conserver == false || record.supprime == false {
                    fichiers_confirmation.push(ConfirmationEtatFuuid { fuuid, supprime: record.supprime });
                }
            }
        }
    }

    if fichiers_confirmation.is_empty() {
        debug!("repondre_fuuids Aucuns fuuids connus, on ne repond pas");
        return Ok(());
    }

    debug!("repondre_fuuids Repondre fuuids connus et non supprimes : {:?}", fichiers_confirmation);
    let confirmation = ReponseConfirmerEtatFuuids { fuuids: fichiers_confirmation };
    let routage = RoutageMessageAction::builder(DOMAINE_FICHIERS_NOM, COMMANDE_ACTIVITE_FUUIDS)
        .exchanges(vec![L2Prive])
        .build();
    middleware.transmettre_commande(routage, &confirmation, false).await?;

    Ok(())
}

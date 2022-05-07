use std::error::Error;

use log::{debug, error, info, warn};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::constantes::Securite;
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, ReturnDocument};
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::tokio_stream::StreamExt;

use crate::constantes::*;
use crate::message_structs::*;
use crate::gestionnaire::GestionnaireMessagerie;
use crate::pompe_messages::{evenement_pompe_poste, verifier_fin_transferts_attachments};

pub async fn consommer_evenement<M>(gestionnaire: &GestionnaireMessagerie, middleware: &M, m: MessageValideAction)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("gestionnaire.consommer_evenement Consommer evenement : {:?}", &m.message);

    // Autorisation selon l'action
    let niveau_securite_requis = match m.action.as_str() {
        EVENEMENT_UPLOAD_ATTACHMENT => Ok(Securite::L1Public),
        EVENEMENT_POMPE_POSTE => Ok(Securite::L4Secure),
        _ => Err(format!("gestionnaire.consommer_evenement: Action inconnue : {}", m.action.as_str())),
    }?;

    if m.verifier_exchanges(vec![niveau_securite_requis.clone()]) {
        match m.action.as_str() {
            EVENEMENT_UPLOAD_ATTACHMENT => evenement_upload_attachment(middleware, m).await,
            EVENEMENT_POMPE_POSTE => evenement_pompe_poste(gestionnaire, middleware, &m).await,
            _ => Err(format!("gestionnaire.consommer_transaction: Mauvais type d'action pour un evenement 1.public : {}", m.action))?,
        }
    } else {
        Err(format!("gestionnaire.consommer_evenement: Niveau de securite invalide pour action {} : doit etre {:?}",
                    m.action.as_str(), niveau_securite_requis))?
    }

}

async fn evenement_upload_attachment<M>(middleware: &M, m: MessageValideAction)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("evenement_upload_attachment Consommer : {:?}", & m.message);
    let evenement: EvenementUploadAttachment = m.message.get_msg().map_contenu(None)?;
    debug!("evenement_upload_attachment parsed : {:?}", evenement);

    let idmg = evenement.idmg.as_str();
    let uuid_message = evenement.uuid_message.as_str();
    let fuuid = evenement.fuuid.as_str();
    let ts_courant = Utc::now().timestamp();

    let ops = match evenement.code {
        CODE_UPLOAD_DEBUT | CODE_UPLOAD_ENCOURS => {
            // Faire un touch
            doc! {
                "$set": { format!("idmgs_mapping.{}.attachments_en_cours.{}.last_update", idmg, fuuid): ts_courant },
                // S'assurer que le fichier n'a pas ete remis dans la file
                "$pull": { format!("idmgs_mapping.{}.attachments_restants", idmg): fuuid, },
                "$currentDate": {CHAMP_LAST_PROCESSED: true},
            }
        },
        CODE_UPLOAD_TERMINE => {
            // Marquer fuuid comme complete
            doc! {
                "$addToSet": { format!("idmgs_mapping.{}.attachments_completes", idmg): fuuid},
                "$unset": { format!("idmgs_mapping.{}.attachments_en_cours.{}", idmg, fuuid): true },
                // S'assurer que le fichier n'a pas ete remis dans la file
                "$pull": { format!("idmgs_mapping.{}.attachments_restants", idmg): fuuid, },
                "$currentDate": {CHAMP_LAST_PROCESSED: true},
            }
        },
        CODE_UPLOAD_ERREUR => {
            warn!("Remettre le fuuid a la fin de la file, ajouter next_push_time");
            return Ok(None);
        },
        _ => {
            Err(format!("evenements.evenement_upload_attachment Recu evenement inconnu (code: {}), on l'ignore", evenement.code))?
        }
    };

    let filtre = doc! {CHAMP_UUID_MESSAGE: uuid_message};
    let options = FindOneAndUpdateOptions::builder()
        .return_document(ReturnDocument::After)
        .build();
    let collection = middleware.get_collection(NOM_COLLECTION_OUTGOING_PROCESSING)?;
    let doc_outgoing = collection.find_one_and_update(filtre, ops, Some(options)).await?;
    let doc_outgoing: DocOutgointProcessing = match doc_outgoing {
        Some(d) => Ok(convertir_bson_deserializable(d)?),
        None => {
            Err(format!("evenements.evenement_upload_attachment Evenement recu pour doc_outgoing inconnu"))
        }
    }?;
    verifier_fin_transferts_attachments(middleware, &doc_outgoing).await?;

    Ok(None)
}

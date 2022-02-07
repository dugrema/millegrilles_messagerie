use std::error::Error;

use log::{debug, error, info, warn};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::constantes::Securite;
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::tokio_stream::StreamExt;

use crate::constantes::*;
use crate::gestionnaire::GestionnaireMessagerie;
use crate::pompe_messages::evenement_pompe_poste;

pub async fn consommer_evenement<M>(gestionnaire: &GestionnaireMessagerie, middleware: &M, m: MessageValideAction)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("gestionnaire.consommer_evenement Consommer evenement : {:?}", &m.message);

    // Autorisation : doit etre de niveau 3.protege ou 4.secure
    match m.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure]) {
        true => Ok(()),
        false => Err(format!("gestionnaire.consommer_evenement: Evenement invalide (pas 3.protege ou 4.secure)")),
    }?;

    match m.action.as_str() {
        EVENEMENT_POMPE_POSTE => evenement_pompe_poste(gestionnaire, middleware, &m).await,
        _ => Err(format!("gestionnaire.consommer_transaction: Mauvais type d'action pour une transaction : {}", m.action))?,
    }
}

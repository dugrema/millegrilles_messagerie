use std::error::Error;
use std::sync::Arc;
use millegrilles_common_rust::tokio::sync::mpsc;
use millegrilles_common_rust::tokio::sync::mpsc::{Receiver, Sender};

use log::{debug, error, info, warn};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::constantes::Securite;
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::tokio_stream::StreamExt;

use crate::constantes::*;
use crate::gestionnaire::GestionnaireMessagerie;

pub async fn traiter_cedule<M>(middleware: &M, trigger: &MessageCedule)
                               -> Result<(), Box<dyn Error>>
where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("pompe_messages.traiter_cedule Cedule message : {:?}", trigger);
    emettre_evenement_pompe(middleware, None).await?;
    Ok(())
}

pub async fn evenement_pompe_poste<M>(gestionnaire: &GestionnaireMessagerie, middleware: &M, m: &MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("pompe_messages.evenement_pompe_poste Evenement recu {:?}", m);
    let tx_pompe = gestionnaire.get_tx_pompe();
    let message = MessagePompe { idmgs: None };
    tx_pompe.send(message).await?;

    Ok(None)
}

/// Emet un evenement pour declencher la pompe de messages au besoin.
pub async fn emettre_evenement_pompe<M>(middleware: &M, idmgs: Option<Vec<String>>)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + MongoDao
{
    let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_POMPE_POSTE)
        .exchanges(vec!(Securite::L4Secure))
        .build();

    let evenement = json!({ "idmgs": idmgs });

    middleware.emettre_evenement(routage, &evenement).await?;

    Ok(())
}

#[derive(Clone, Debug)]
pub struct MessagePompe {
    idmgs: Option<Vec<String>>,
}

#[derive(Debug)]
pub struct PompeMessages {
    rx: Receiver<MessagePompe>,
    tx: Sender<MessagePompe>,
}

impl PompeMessages {

    pub fn new() -> PompeMessages {
        let (tx, rx) = mpsc::channel(1);
        return PompeMessages{ rx, tx }
    }

    pub fn get_tx_pompe(&self) -> Sender<MessagePompe> {
        self.tx.clone()
    }

    pub async fn run<M>(mut self, middleware: Arc<M>)
        where M: GenerateurMessages + MongoDao
    {
        debug!("Running thread pompe");

        while let Some(message) = self.rx.recv().await {
            debug!("pompe_messages.run Message recu : {:?}", message);
        }

        debug!("Fin thread pompe");
    }
}

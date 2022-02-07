use std::error::Error;
use std::sync::Arc;

use millegrilles_common_rust::tokio::sync::mpsc;
use millegrilles_common_rust::tokio::sync::mpsc::{Receiver, Sender};
use millegrilles_common_rust::mongodb::options::{AggregateOptions, CountOptions, FindOptions, Hint, UpdateOptions};

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
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::tokio_stream::StreamExt;

use crate::constantes::*;
use crate::gestionnaire::GestionnaireMessagerie;
use crate::message_structs::*;

pub async fn traiter_cedule<M>(middleware: &M, trigger: &MessageCedule)
                               -> Result<(), Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("pompe_messages.traiter_cedule Cedule message : {:?}", trigger);

    // Mettre un trigger d'execution de la pompe sur MQ, permet de gerer flow de maniere externe au besoin
    emettre_evenement_pompe(middleware, None).await?;

    Ok(())
}

pub async fn evenement_pompe_poste<M>(gestionnaire: &GestionnaireMessagerie, middleware: &M, m: &MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("pompe_messages.evenement_pompe_poste Evenement recu {:?}", m);
    let tx_pompe = gestionnaire.get_tx_pompe();
    let message: MessagePompe = m.message.parsed.map_contenu(None)?;
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

#[derive(Clone, Debug, Serialize, Deserialize)]
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
        return PompeMessages { rx, tx };
    }

    pub fn get_tx_pompe(&self) -> Sender<MessagePompe> {
        self.tx.clone()
    }

    /// Thread d'execution de la pompe.
    pub async fn run<M>(mut self, middleware: Arc<M>)
        where M: GenerateurMessages + MongoDao
    {
        debug!("pompe_messages.PompeMessages Running thread pompe");

        while let Some(message) = self.rx.recv().await {
            debug!("pompe_messages.run Trigger recu : {:?}", message);
            match self.cycle_pompe_messages(middleware.as_ref(), &message).await {
                Ok(_) => (),
                Err(e) => error!("pompe_messages.run Erreur runtime : {:?}", e)
            }
        }

        debug!("pompe_messages.PompeMessages Fin thread pompe");
    }

    async fn cycle_pompe_messages<M>(&mut self, middleware: &M, trigger: &MessagePompe)
        -> Result<(), Box<dyn Error>>
        where M: GenerateurMessages + MongoDao
    {
        let idmgs = get_batch_idmgs(middleware, trigger).await?;

        Ok(())
    }
}

async fn get_batch_idmgs<M>(middleware: &M, trigger: &MessagePompe)
    -> Result<Vec<String>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao
{
    let collection = middleware.get_collection(NOM_COLLECTION_OUTGOING_PROCESSING)?;

    let mut filtre = doc! {};
    if let Some(idmgs) = &trigger.idmgs {
        filtre.insert("idmgs_unprocessed", doc! {"$all": idmgs});
    }

    let options = AggregateOptions::builder()
        .build();

    let pipeline = vec! [
        // Match sur les idmgs specifies au besoin. Limiter matching si grande quantite en attente.
        doc! {"$match": filtre},
        // Expansion de tous les idmgs par message
        doc! {"$unwind": {"path": "$idmgs_unprocessed"}},
        // Grouper par date last_processed, permet d'aller chercher les plus vieux messages
        doc! {"$group": {"_id": "$idmgs_unprocessed", "last_date": {"$min": "$last_processed"}}},
        // Plus vieux en premier
        doc! {"$sort": {"last_date": 1}},
        // Mettre une limite dans la batch de retour
        doc! {"$limit": 1},
    ];
    debug!("pompe_messages.get_batch_idmgs Pipeline idmgs a loader : {:?}", pipeline);

    let mut curseur = collection.aggregate(pipeline, Some(options)).await?;
    let mut resultat: Vec<String> = Vec::new();
    while let Some(r) = curseur.next().await {
        let doc = r?;
        debug!("Result data : {:?}", doc);
        let idmg = doc.get_str("_id")?;
        resultat.push(idmg.into());
    }

    debug!("pompe_messages.get_batch_idmgs Resultat : {:?}", resultat);

    Ok(resultat)
}

// Retourne une batch de messages non traites pour un idmg.
// async fn get_batch_messages<M>(middleware: &M, idmg: String)
//     -> Result<Vec<DocOutgointProcessing>, Box<dyn Error>>
//     where M: GenerateurMessages + MongoDao
// {
//
// }

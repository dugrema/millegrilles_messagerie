use std::error::Error;
use std::sync::Arc;

use millegrilles_common_rust::tokio::sync::mpsc;
use millegrilles_common_rust::tokio::sync::mpsc::{Receiver, Sender};
use millegrilles_common_rust::mongodb::options::{AggregateOptions, CountOptions, FindOptions, Hint, UpdateOptions};

use log::{debug, error, info, warn};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::constantes::{Securite, SECURITE_2_PRIVE};
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json;
use millegrilles_common_rust::serde_json::{json, Map, Value};
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

pub async fn evenement_pompe_poste<M>(gestionnaire: &GestionnaireMessagerie, middleware: &M, m: &MessageValideAction)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
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

        for idmg in idmgs {
            let batch = get_batch_messages(middleware, idmg.as_str()).await?;
            debug!("Traiter batch messages : {:?}", batch);
            traiter_batch_messages(middleware, idmg.as_str(), &batch).await?;
        }

        Ok(())
    }
}

async fn get_batch_idmgs<M>(middleware: &M, trigger: &MessagePompe)
    -> Result<Vec<String>, Box<dyn Error>>
    where M: MongoDao
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
async fn get_batch_messages<M>(middleware: &M, idmg: &str)
    -> Result<Vec<DocOutgointProcessing>, Box<dyn Error>>
    where M: MongoDao
{
    debug!("pompe_messages.get_batch_messages Idmg {}", idmg);
    let collection = middleware.get_collection(NOM_COLLECTION_OUTGOING_PROCESSING)?;

    let filtre = doc! { "idmgs_unprocessed": {"$all": [idmg]} };
    let sort = doc! { "last_processed": 1 };
    let options = FindOptions::builder()
        .sort(sort)
        .limit(5)
        .build();

    let mut curseur = collection.find(filtre, Some(options)).await?;
    let mut resultat: Vec<DocOutgointProcessing> = Vec::new();
    while let Some(r) = curseur.next().await {
        let doc = r?;
        // debug!("Result data : {:?}", doc);
        let message_outgoing: DocOutgointProcessing = convertir_bson_deserializable(doc)?;
        resultat.push(message_outgoing);
    }

    // debug!("pompe_messages.get_batch_messages Resultat : {:?}", resultat);

    Ok(resultat)
}

async fn traiter_batch_messages<M>(middleware: &M, idmg_traitement: &str, messages_outgoing: &Vec<DocOutgointProcessing>)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + MongoDao
{
    debug!("pompe_messages.traiter_batch_messages Traiter batch {} messages", messages_outgoing.len());

    let idmg_local = middleware.get_enveloppe_privee().idmg()?;
    if idmg_local == idmg_traitement {
        debug!("Traitement messages pour idmg local : {}", idmg_traitement);
        for message in messages_outgoing {
            pousser_message_local(middleware, message).await?;
        }
    } else {
        Err(format!("MilleGrille tierce non supportee (IDMG: {})", idmg_traitement))?
    };

    Ok(())
}

/// Pousse des messages locaux. Transfere le contenu dans la reception de chaque destinataire.
async fn pousser_message_local<M>(middleware: &M, message: &DocOutgointProcessing) -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + MongoDao
{
    debug!("Pousser message : {:?}", message);
    let uuid_transaction = message.uuid_transaction.as_str();

    // Mapping idmg local
    let idmg_local = middleware.get_enveloppe_privee().idmg()?;
    let mapping: &DocMappingIdmg = if let Some(m) = message.idmgs_mapping.as_ref() {
        match m.get(idmg_local.as_str()) {
            Some(m) => Ok(m),
            None => Err(format!("Aucun mapping trouve dans message {} pour idmg local {}", uuid_transaction, idmg_local))
        }
    } else {
        Err(format!("Aucun mapping trouve dans message {} pour idmg local {}", uuid_transaction, idmg_local))
    }?;

    let mut destinataires = Vec::new();

    // Identifier destinataires qui correspondent via DNS
    if let Some(mapping_dns) = mapping.dns.as_ref() {
        if let Some(d) = message.destinataires.as_ref() {
            for dest in d {
                if let Some(dns_destinataire) = dest.dns.as_ref() {
                    if mapping_dns.contains(dns_destinataire) {
                        if let Some(u) = dest.user.as_ref() {
                            destinataires.push(u.clone());
                        }
                    }
                }
            }
        }
    }

    debug!("Mapping destinataires pour idmg {}, message {} : {:?}", idmg_local, uuid_transaction, destinataires);

    // Charger transaction message
    let doc = {
        let collection_transactions = middleware.get_collection(NOM_COLLECTION_TRANSACTIONS)?;
        let filtre_transaction = doc! { "en-tete.uuid_transaction": uuid_transaction };
        let doc = collection_transactions.find_one(filtre_transaction, None).await?;
        if let Some(d) = doc {
            d
        } else {
            Err(format!("pompe_messages.pousser_message_local Transaction pour message {} introuvable", uuid_transaction))?
        }
    };

    debug!("Message a transmettre : {:?}", doc);
    let mut val = match serde_json::to_value(doc) {
        Ok(v) => match v.as_object() {
            Some(o) => o.to_owned(),
            None => Err(format!("Erreur sauvegarde transaction, mauvais type objet JSON"))?,
        },
        Err(e) => Err(format!("Erreur sauvegarde transaction, conversion : {:?}", e))?,
    };

    let mut keys_to_remove = Vec::new();
    for key in val.keys() {
        if key.starts_with("_") && key != "_signature" && key != "_bcc" {
            keys_to_remove.push(key.to_owned());
        }
    }
    for key in keys_to_remove {
        val.remove(key.as_str());
    }
    debug!("Message mappe : {:?}", val);

    // Emettre commande recevoir
    let commande = CommandeRecevoirPost{ message: val, destinataires: destinataires.clone(), };
    let routage = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_RECEVOIR)
        .exchanges(vec![Securite::L2Prive])
        .build();

    // TODO - Mettre pompe sur sa propre Q, blocking true
    middleware.transmettre_commande(routage, &commande, false).await?;
    // debug!("Reponse commande message local : {:?}", reponse);

    // TODO - Fix verif confirmation. Ici on assume un succes
    {
        debug!("Marquer idmg {} comme pousse pour message {}", idmg_local, uuid_transaction);

        // Marquer process comme succes pour reception sur chaque usager
        let collection_outgoing_processing = middleware.get_collection(NOM_COLLECTION_OUTGOING_PROCESSING)?;
        let filtre_outgoing = doc! { "uuid_transaction": uuid_transaction };
        let array_filters = vec! [
            doc! {"dest.user": {"$in": destinataires }}
        ];
        let options = UpdateOptions::builder()
            .array_filters(array_filters)
            .build();
        let ops = doc! {
            "$pull": {"idmgs_unprocessed": &idmg_local},
            "$set": {
                "destinataires.$[dest].processed": true,
                "destinataires.$[dest].result": 201,
            },
            "$currentDate": {"last_processed": true}
        };

        let resultat = collection_outgoing_processing.update_one(filtre_outgoing, ops, Some(options)).await?;
        debug!("Resultat marquer idmg {} comme pousse pour message {} : {:?}", idmg_local, uuid_transaction, resultat);
    }

    Ok(())
}

use std::collections::{HashMap, HashSet};
use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::sync::{Arc, Mutex};

use log::{debug, error, warn};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chiffrage::CommandeSauvegarderCle;
use millegrilles_common_rust::{chrono, chrono::{DateTime, Utc}};
use millegrilles_common_rust::chrono::Timelike;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille};
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::{Middleware, sauvegarder_traiter_transaction, sauvegarder_transaction_recue};
use millegrilles_common_rust::mongo_dao::{ChampIndex, convertir_bson_deserializable, convertir_to_bson, filtrer_doc_id, IndexOptions, MongoDao};
use millegrilles_common_rust::mongodb::Cursor;
use millegrilles_common_rust::mongodb::options::{CountOptions, FindOptions, Hint, UpdateOptions};
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType};
use millegrilles_common_rust::recepteur_messages::{MessageValideAction, TypeMessage};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::tokio::spawn;
use millegrilles_common_rust::tokio::sync::mpsc::Sender;
use millegrilles_common_rust::tokio::task::JoinHandle;
use millegrilles_common_rust::tokio::time::{Duration, sleep};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::{TraiterTransaction, Transaction, TransactionImpl};
use millegrilles_common_rust::verificateur::VerificateurMessage;

use crate::commandes::consommer_commande;
use crate::constantes::*;
use crate::evenements::consommer_evenement;
use crate::pompe_messages::{MessagePompe, PompeMessages, traiter_cedule as traiter_cedule_pompe};
use crate::requetes::consommer_requete;
use crate::transactions::*;

#[derive(Debug)]
pub struct GestionnaireMessagerie {
    tx_pompe_messages: Mutex<Option<Sender<MessagePompe>>>,
}

impl Clone for GestionnaireMessagerie {
    fn clone(&self) -> Self {
        GestionnaireMessagerie {
            tx_pompe_messages: Mutex::new(Some(self.get_tx_pompe()))
        }
    }
}

impl GestionnaireMessagerie {
    pub fn new() -> GestionnaireMessagerie {
        return GestionnaireMessagerie { tx_pompe_messages: Mutex::new(None) }
    }
    pub fn get_tx_pompe(&self) -> Sender<MessagePompe> {
        let guard = self.tx_pompe_messages.lock().expect("lock tx pompe");
        match guard.as_ref() {
            Some(p) => p.clone(),
            None => panic!("TX pompe message n'est pas configuree")
        }
    }
}

#[async_trait]
impl TraiterTransaction for GestionnaireMessagerie {
    async fn appliquer_transaction<M>(&self, middleware: &M, transaction: TransactionImpl) -> Result<Option<MessageMilleGrille>, String>
        where M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(self, middleware, transaction).await
    }
}

#[async_trait]
impl GestionnaireDomaine for GestionnaireMessagerie {
    fn get_nom_domaine(&self) -> String { String::from(DOMAINE_NOM) }

    fn get_collection_transactions(&self) -> String { String::from(NOM_COLLECTION_TRANSACTIONS) }

    fn get_collections_documents(&self) -> Vec<String> { vec![
        String::from(NOM_COLLECTION_INCOMING),
        // String::from(NOM_COLLECTION_OUTGOING),
        String::from(NOM_COLLECTION_OUTGOING_PROCESSING),
        String::from(NOM_COLLECTION_ATTACHMENTS),
        String::from(NOM_COLLECTION_ATTACHMENTS_PROCESSING),
        String::from(NOM_COLLECTION_PROFILS),
        String::from(NOM_COLLECTION_CONTACTS),
    ] }

    fn get_q_transactions(&self) -> String { String::from(NOM_Q_TRANSACTIONS) }

    fn get_q_volatils(&self) -> String { String::from(NOM_Q_VOLATILS) }

    fn get_q_triggers(&self) -> String { String::from(NOM_Q_TRIGGERS) }

    fn preparer_queues(&self) -> Vec<QueueType> { preparer_queues() }

    fn chiffrer_backup(&self) -> bool {
        true
    }

    async fn preparer_index_mongodb_custom<M>(&self, middleware: &M) -> Result<(), String> where M: MongoDao {
        preparer_index_mongodb_custom(middleware).await
    }

    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: Middleware + 'static {
        consommer_requete(middleware, message, &self).await
    }

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: Middleware + 'static {
        consommer_commande(middleware, message, &self).await
    }

    async fn consommer_transaction<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: Middleware + 'static {
        consommer_transaction(middleware, message).await
    }

    async fn consommer_evenement<M>(self: &'static Self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: Middleware + 'static {
        consommer_evenement(self, middleware, message).await
    }

    async fn entretien<M>(&self, middleware: Arc<M>) where M: Middleware + 'static {
        entretien(self, middleware).await
    }

    async fn traiter_cedule<M>(self: &'static Self, middleware: &M, trigger: &MessageCedule)
        -> Result<(), Box<dyn Error>>
        where M: Middleware + 'static
    {
        traiter_cedule(self, middleware, trigger).await
    }

    async fn aiguillage_transaction<M, T>(&self, middleware: &M, transaction: T)
        -> Result<Option<MessageMilleGrille>, String>
        where M: ValidateurX509 + GenerateurMessages + MongoDao, T: Transaction
    {
        aiguillage_transaction(self, middleware, transaction).await
    }

    async fn preparer_threads<M>(self: &'static Self, middleware: Arc<M>)
        -> Result<(HashMap<String, Sender<TypeMessage>>, FuturesUnordered<JoinHandle<()>>), Box<dyn Error>>
        where M: Middleware + 'static
    {
        // Super
        let (
            senders,
            mut futures
        ) = self.preparer_threads_super(middleware.clone()).await?;

        // Ajouter pompe dans futures
        let pompe = PompeMessages::new();
        {
            // Injecter tx pour messages de pompe dans le guestionnaire
            let mut tx_guard = self.tx_pompe_messages.lock().expect("lock tx guard");
            *tx_guard = Some(pompe.get_tx_pompe());
        }
        futures.push(spawn(pompe.run(middleware.clone())));

        Ok((senders, futures))
    }

}

pub fn preparer_queues() -> Vec<QueueType> {
    let mut rk_volatils = Vec::new();
    //let mut rk_sauvegarder_cle = Vec::new();

    // RK 2.prive
    let requetes_privees: Vec<&str> = vec![
        REQUETE_GET_MESSAGES,
        REQUETE_GET_PERMISSION_MESSAGES,
        REQUETE_GET_PROFIL,
        REQUETE_GET_CONTACTS,
        REQUETE_ATTACHMENT_REQUIS,
    ];
    for req in requetes_privees {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, req), exchange: Securite::L2Prive});
    }

    let commandes_privees: Vec<&str> = vec![
        TRANSACTION_POSTER,
        TRANSACTION_RECEVOIR,
        TRANSACTION_INITIALISER_PROFIL,
        TRANSACTION_MAJ_CONTACT,
        TRANSACTION_LU,

        // COMMANDE_INDEXER,
    ];
    for cmd in commandes_privees {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, cmd), exchange: Securite::L2Prive});
    }

    let commandes_publiques: Vec<&str> = vec![
        COMMANDE_CONFIRMER_TRANSMISSION,
        COMMANDE_PROCHAIN_ATTACHMENT,
    ];
    for cmd in commandes_publiques {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, cmd), exchange: Securite::L1Public});
    }

    let evenements_secure: Vec<&str> = vec![ EVENEMENT_POMPE_POSTE ];
    for cmd in evenements_secure {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", DOMAINE_NOM, cmd), exchange: Securite::L4Secure});
    }

    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", DOMAINE_POSTMASTER, EVENEMENT_UPLOAD_ATTACHMENT), exchange: Securite::L1Public});

    let mut queues = Vec::new();

    // Queue de messages volatils (requete, commande, evenements)
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: NOM_Q_VOLATILS.into(),
            routing_keys: rk_volatils,
            ttl: DEFAULT_Q_TTL.into(),
            durable: true,
        }
    ));

    let mut rk_transactions = Vec::new();
    let transactions_secures: Vec<&str> = vec![
        TRANSACTION_POSTER,
        TRANSACTION_RECEVOIR,
        TRANSACTION_INITIALISER_PROFIL,
        TRANSACTION_MAJ_CONTACT,
        TRANSACTION_LU,
        TRANSACTION_TRANSFERT_COMPLETE,
    ];
    for ts in transactions_secures {
        rk_transactions.push(ConfigRoutingExchange {
            routing_key: format!("transaction.{}.{}", DOMAINE_NOM, ts).into(),
            exchange: Securite::L4Secure
        });
    }

    // RK protege
    let transactions_protegees: Vec<&str> = vec![
        // TRANSACTION_ASSOCIER_CONVERSIONS,
        // TRANSACTION_ASSOCIER_VIDEO,
    ];
    for t in transactions_protegees {
        rk_transactions.push(ConfigRoutingExchange {
            routing_key: format!("transaction.{}.{}", DOMAINE_NOM, t).into(),
            exchange: Securite::L3Protege
        });
    }

    // Queue de transactions
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: NOM_Q_TRANSACTIONS.into(),
            routing_keys: rk_transactions,
            ttl: None,
            durable: true,
        }
    ));

    // Queue de triggers pour Pki
    queues.push(QueueType::Triggers (DOMAINE_NOM.into(), Securite::L3Protege));

    // Queue de pompe de messages
    // let mut rk_pompe = Vec::new();
    // rk_pompe.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", DOMAINE_NOM, EVENEMENT_POMPE_POSTE), exchange: Securite::L4Secure});
    // queues.push(QueueType::ExchangeQueue (
    //     ConfigQueue {
    //         nom_queue: NOM_Q_MESSAGE_POMPE.into(),
    //         routing_keys: rk_pompe,
    //         ttl: DEFAULT_Q_TTL.into(),
    //         durable: true,
    //     }
    // ));

    queues
}

/// Creer index MongoDB
pub async fn preparer_index_mongodb_custom<M>(middleware: &M) -> Result<(), String>
    where M: MongoDao
{
    // Index uuid_transaction pour messages_outgoing
    let options_unique_outgoing_transactions_uuid_transaction = IndexOptions {
        nom_index: Some(String::from("uuid_transaction")),
        unique: true
    };
    let champs_index_outgoing_transactions_uuid_transactions = vec!(
        ChampIndex {nom_champ: String::from("uuid_transaction"), direction: 1},
    );
    middleware.create_index(
        NOM_COLLECTION_OUTGOING_PROCESSING,
        champs_index_outgoing_transactions_uuid_transactions,
        Some(options_unique_outgoing_transactions_uuid_transaction)
    ).await?;

    // Index uuid_message pour messages_outgoing
    let options_unique_outgoing_transactions_uuid_transaction = IndexOptions {
        nom_index: Some(String::from("uuid_message")),
        unique: true
    };
    let champs_index_outgoing_transactions_uuid_transactions = vec!(
        ChampIndex {nom_champ: String::from("uuid_message"), direction: 1},
    );
    middleware.create_index(
        NOM_COLLECTION_OUTGOING_PROCESSING,
        champs_index_outgoing_transactions_uuid_transactions,
        Some(options_unique_outgoing_transactions_uuid_transaction)
    ).await?;

    // Index idmg_unprocessed, last_processed
    let options_unprocessed = IndexOptions {
        nom_index: Some(String::from("unprocessed")),
        unique: false
    };
    let champs_index_unprocessed = vec!(
        ChampIndex {nom_champ: String::from("last_processed"), direction: 1},
        ChampIndex {nom_champ: String::from("idmgs_unprocessed"), direction: 1},
    );
    middleware.create_index(
        NOM_COLLECTION_OUTGOING_PROCESSING,
        champs_index_unprocessed,
        Some(options_unprocessed)
    ).await?;

    // Index dns_unresolved
    let options_dns_unresolved = IndexOptions {
        nom_index: Some(String::from("dns_unresolved")),
        unique: false
    };
    let champs_index_dns_unresolved = vec!(
        ChampIndex {nom_champ: String::from("created"), direction: 1},
        ChampIndex {nom_champ: String::from("dns_unresolved"), direction: 1},
    );
    middleware.create_index(
        NOM_COLLECTION_OUTGOING_PROCESSING,
        champs_index_dns_unresolved,
        Some(options_dns_unresolved)
    ).await?;

    // Index user_id, uuid_transaction pour messages incoming
    let options_incoming_userid = IndexOptions {
        nom_index: Some(String::from("userid_uuidtransaction")),
        unique: true
    };
    let champs_incoming_userid = vec!(
        ChampIndex {nom_champ: String::from("user_id"), direction: 1},
        ChampIndex {nom_champ: String::from("uuid_transaction"), direction: 1},
    );
    middleware.create_index(
        NOM_COLLECTION_INCOMING,
        champs_incoming_userid,
        Some(options_incoming_userid)
    ).await?;

    // Index user_id, uuid_transaction pour messages incoming
    let options_attachments_fuuids = IndexOptions {
        nom_index: Some(String::from("attachments_fuuid")),
        unique: false
    };
    let champs_attachments_fuuids = vec!(
        ChampIndex {nom_champ: String::from("attachments"), direction: 1},
    );
    middleware.create_index(
        NOM_COLLECTION_INCOMING,
        champs_attachments_fuuids,
        Some(options_attachments_fuuids)
    ).await?;

    Ok(())
}

pub async fn entretien<M>(_gestionnaire: &GestionnaireMessagerie, _middleware: Arc<M>)
    where M: Middleware + 'static
{
    loop {
        sleep(Duration::new(30, 0)).await;
        debug!("Cycle entretien {}", DOMAINE_NOM);
    }
}

pub async fn traiter_cedule<M>(gestionnaire: &GestionnaireMessagerie, middleware: &M, trigger: &MessageCedule)
                               -> Result<(), Box<dyn Error>>
    where M: Middleware + 'static
{
    debug!("Traiter cedule {}", DOMAINE_NOM);

    let mut prochain_entretien_index_media = chrono::Utc::now();
    let intervalle_entretien_index_media = chrono::Duration::minutes(5);

    let date_epoch = trigger.get_date();
    let minutes = date_epoch.get_datetime().minute();

    // Relai message vers pompe
    if let Err(e) = traiter_cedule_pompe(middleware, trigger).await {
        error!("gestionnaire.traiter_cedule Erreur cedule pompe: {:?}", e);
    }

    // Executer a toutes les 5 minutes
    // if minutes % 5 == 0 {
    // }

    Ok(())
}

#[cfg(test)]
mod test_integration {
    use millegrilles_common_rust::backup::CatalogueHoraire;
    use millegrilles_common_rust::formatteur_messages::MessageSerialise;
    use millegrilles_common_rust::generateur_messages::RoutageMessageAction;
    use millegrilles_common_rust::middleware::IsConfigurationPki;
    use millegrilles_common_rust::middleware_db::preparer_middleware_db;
    use millegrilles_common_rust::mongo_dao::convertir_to_bson;
    use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
    use millegrilles_common_rust::recepteur_messages::TypeMessage;
    use millegrilles_common_rust::tokio as tokio;

    use crate::test_setup::setup;

    use super::*;

// #[tokio::test]
    // async fn test_requete_compte_non_dechiffrable() {
    //     setup("test_requete_compte_non_dechiffrable");
    //     let (middleware, _, _, mut futures) = preparer_middleware_db(Vec::new(), None);
    //     let enveloppe_privee = middleware.get_enveloppe_privee();
    //     let fingerprint = enveloppe_privee.fingerprint().as_str();
    //
    //     let gestionnaire = GestionnaireGrosFichiers {fingerprint: fingerprint.into()};
    //     futures.push(tokio::spawn(async move {
    //
    //         let contenu = json!({});
    //         let message_mg = MessageMilleGrille::new_signer(
    //             enveloppe_privee.as_ref(),
    //             &contenu,
    //             DOMAINE_NOM.into(),
    //             REQUETE_COMPTER_CLES_NON_DECHIFFRABLES.into(),
    //             None::<&str>,
    //             None
    //         ).expect("message");
    //         let mut message = MessageSerialise::from_parsed(message_mg).expect("serialise");
    //
    //         // Injecter certificat utilise pour signer
    //         message.certificat = Some(enveloppe_privee.enveloppe.clone());
    //
    //         let mva = MessageValideAction::new(
    //             message, "dummy_q", "routing_key", "domaine", "action", TypeMessageOut::Requete);
    //
    //         let reponse = requete_compter_cles_non_dechiffrables(middleware.as_ref(), mva, &gestionnaire).await.expect("dechiffrage");
    //         debug!("Reponse requete compte cles non dechiffrables : {:?}", reponse);
    //
    //     }));
    //     // Execution async du test
    //     futures.next().await.expect("resultat").expect("ok");
    // }

}


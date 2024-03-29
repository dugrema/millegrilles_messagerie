//! Module SenseursPassifs de millegrilles installe sur un noeud 3.protege.

use std::collections::HashMap;
use std::sync::Arc;

use log::{debug, error, info, warn};
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::chrono as chrono;
use millegrilles_common_rust::configuration::{charger_configuration, IsConfigNoeud};
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::middleware::Middleware;
use millegrilles_common_rust::middleware_db::{MiddlewareDb, preparer_middleware_db};
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::recepteur_messages::TypeMessage;
use millegrilles_common_rust::tokio::{sync::mpsc::{Receiver, Sender}, time::Duration as DurationTokio};
use millegrilles_common_rust::tokio::spawn;
use millegrilles_common_rust::tokio::task::JoinHandle;
use millegrilles_common_rust::tokio::time::sleep;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::resoumettre_transactions;

use crate::gestionnaire::GestionnaireMessagerie;

const DUREE_ATTENTE: u64 = 20000;

// Creer espace static pour conserver les gestionnaires

static mut GESTIONNAIRE: TypeGestionnaire = TypeGestionnaire::None;

/// Enum pour distinger les types de gestionnaires.
#[derive(Clone, Debug)]
enum TypeGestionnaire {
    PartitionConsignation(Arc<GestionnaireMessagerie>),
    None
}

pub async fn run() {

    // Init gestionnaires ('static)
    let gestionnaire = charger_gestionnaire();

    // Wiring
    let (futures, _) = build(gestionnaire).await;

    // Run
    executer(futures).await
}

/// Fonction qui lit le certificat local et extrait les fingerprints idmg et de partition
/// Conserve les gestionnaires dans la variable GESTIONNAIRES 'static
fn charger_gestionnaire() -> &'static TypeGestionnaire {
    // Charger une version simplifiee de la configuration - on veut le certificat associe a l'enveloppe privee
    // let config = charger_configuration().expect("config");
    // let config_noeud = config.get_configuration_noeud();
    // let elastic_search_url = match &config_noeud.elastic_search_url {
    //     Some(inner) => inner,
    //     None => panic!("URL MG_ELASTICSEARCH_URL doit etre fourni")
    // };

    // Inserer les gestionnaires dans la variable static - permet d'obtenir lifetime 'static
    unsafe {
        GESTIONNAIRE = TypeGestionnaire::PartitionConsignation(Arc::new(GestionnaireMessagerie::new() ));
        &GESTIONNAIRE
    }
}

async fn build(gestionnaire: &'static TypeGestionnaire) -> (FuturesUnordered<JoinHandle<()>>, Arc<MiddlewareDb>) {

    // Recuperer configuration des Q de tous les domaines
    // let queues = {
    //     let mut queues: Vec<QueueType> = Vec::new();
    //     //for g in gestionnaires.clone() {
    //         match gestionnaire {
    //             TypeGestionnaire::PartitionConsignation(g) => {
    //                 queues.extend(g.preparer_queues());
    //             },
    //             TypeGestionnaire::None => ()
    //         }
    //     //}
    //     queues
    // };

    let middleware_hooks = preparer_middleware_db();
    let middleware = middleware_hooks.middleware;

    // Preparer les green threads de tous les domaines/processus
    let mut futures = FuturesUnordered::new();
    {
        // ** Domaines **
        {
            let futures_g = match gestionnaire {
                TypeGestionnaire::PartitionConsignation(g) => {
                    g.preparer_threads(middleware.clone()).await.expect("gestionnaire")
                },
                TypeGestionnaire::None => FuturesUnordered::new(),
            };
            futures.extend(futures_g);        // Deplacer vers futures globaux
        }

        // ** Thread d'entretien **
        futures.push(spawn(entretien(middleware.clone(), vec![gestionnaire])));

        // Thread ecoute et validation des messages
        for f in middleware_hooks.futures {
            futures.push(f);
        }
    }

    (futures, middleware)
}

async fn executer(mut futures: FuturesUnordered<JoinHandle<()>>) {
    info!("domaines_messagerie: Demarrage traitement, top level threads {}", futures.len());
    let arret = futures.next().await;
    info!("domaines_messagerie: Fermeture du contexte, task daemon terminee : {:?}", arret);
}

/// Thread d'entretien
async fn entretien<M>(middleware: Arc<M>, gestionnaires: Vec<&'static TypeGestionnaire>)
    where M: Middleware
{
    let mut certificat_emis = false;

    // Liste de collections de transactions pour tous les domaines geres par Core
    let collections_transaction = {
        let mut coll_docs_strings = Vec::new();
        for g in &gestionnaires {
            match g {
                TypeGestionnaire::PartitionConsignation(g) => {
                    if let Some(nom_collection) = g.get_collection_transactions() {
                        coll_docs_strings.push(nom_collection);
                    }
                },
                TypeGestionnaire::None => ()
            }
        }
        coll_docs_strings
    };

    // let mut rechiffrage_complete = false;

    let mut prochain_chargement_certificats_maitredescles = chrono::Utc::now();
    let intervalle_chargement_certificats_maitredescles = chrono::Duration::minutes(5);

    let mut prochain_entretien_transactions = chrono::Utc::now();
    let intervalle_entretien_transactions = chrono::Duration::minutes(5);

    // let mut prochain_sync = chrono::Utc::now();
    // let intervalle_sync = chrono::Duration::hours(6);

    // let mut prochaine_confirmation_ca = chrono::Utc::now();
    // let intervalle_confirmation_ca = chrono::Duration::minutes(15);

    // let mut prochain_chargement_certificats_autres = chrono::Utc::now();
    // let intervalle_chargement_certificats_autres = chrono::Duration::minutes(5);

    // let mut prochain_entretien_elasticsearch = chrono::Utc::now();
    // let intervalle_entretien_elasticsearch = chrono::Duration::minutes(5);

    info!("domaines_messagerie.entretien : Debut thread dans 5 secondes");

    // Donner 5 secondes pour que les Q soient pretes (e.g. Q reponse)
    sleep(DurationTokio::new(5, 0)).await;

    loop {
        let maintenant = chrono::Utc::now();
        debug!("domaines_messagerie.entretien  Execution task d'entretien Core {:?}", maintenant);

        if prochain_chargement_certificats_maitredescles < maintenant {
            match middleware.charger_certificats_chiffrage(middleware.as_ref()).await {
                Ok(()) => {
                    prochain_chargement_certificats_maitredescles = maintenant + intervalle_chargement_certificats_maitredescles;
                },
                Err(e) => info!("Erreur chargement certificats de maitre des cles tiers : {:?}", e)
            }
        }

        // Sleep jusqu'au prochain entretien ou evenement MQ (e.g. connexion)
        debug!("domaines_messagerie.entretien Fin cycle, sleep {} secondes", DUREE_ATTENTE / 1000);
        let duration = DurationTokio::from_millis(DUREE_ATTENTE);
        sleep(duration).await;

        middleware.entretien_validateur().await;

        if prochain_entretien_transactions < maintenant {
            let resultat = resoumettre_transactions(
                middleware.as_ref(),
                &collections_transaction
            ).await;

            match resultat {
                Ok(_) => {
                    prochain_entretien_transactions = maintenant + intervalle_entretien_transactions;
                },
                Err(e) => {
                    warn!("domaines_messagerie.entretien Erreur resoumission transactions (entretien) : {:?}", e);
                }
            }
        }

        if certificat_emis == false {
            debug!("domaines_messagerie.entretien Emettre certificat");
            match middleware.emettre_certificat(middleware.as_ref()).await {
                Ok(()) => certificat_emis = true,
                Err(e) => error!("Erreur emission certificat local : {:?}", e),
            }
            debug!("domaines_messagerie.entretien Fin emission traitement certificat local, resultat : {}", certificat_emis);
        }

        for g in &gestionnaires {
            match g {
                TypeGestionnaire::PartitionConsignation(_g) => {
                    debug!("Entretien Messagerie noeud protege");
                    // if prochain_entretien_elasticsearch < maintenant {
                    //     prochain_entretien_elasticsearch = maintenant + intervalle_entretien_elasticsearch;
                    //     if !g.es_est_pret() {
                    //         info!("Preparer ElasticSearch");
                    //         match g.es_preparer().await {
                    //             Ok(()) => {
                    //                 info!("Index ElasticSearch prets");
                    //             },
                    //             Err(e) => warn!("domaines_messagerie.entretien Erreur preparation ElasticSearch : {:?}", e)
                    //         }
                    //     }
                    // }
                },
                _ => ()
            }
        }

    }

    // panic!("Forcer fermeture");
    // info!("domaines_messagerie.entretien : Fin thread");
}

// async fn consommer(
//     _middleware: Arc<impl ValidateurX509 + GenerateurMessages + MongoDao>,
//     mut rx: Receiver<TypeMessage>,
//     map_senders: HashMap<String, Sender<TypeMessage>>
// ) {
//     info!("domaines_messagerie.consommer : Debut thread, mapping : {:?}", map_senders.keys());
//
//     while let Some(message) = rx.recv().await {
//         match &message {
//             TypeMessage::Valide(m) => {
//                 warn!("domaines_messagerie.consommer: Message valide sans routing key/action : {:?}", m.message);
//             },
//             TypeMessage::ValideAction(m) => {
//                 let contenu = &m.message;
//                 let rk = m.routing_key.as_str();
//                 let action = m.action.as_str();
//                 let domaine = m.domaine.as_str();
//                 let nom_q = m.q.as_str();
//                 info!("domaines_messagerie.consommer: Traiter message valide (action: {}, rk: {}, q: {})", action, rk, nom_q);
//                 debug!("domaines_messagerie.consommer: Traiter message valide contenu {:?}", contenu);
//
//                 // Tenter de mapper avec le nom de la Q (ne fonctionnera pas pour la Q de reponse)
//                 let sender = match map_senders.get(nom_q) {
//                     Some(sender) => {
//                         debug!("domaines_messagerie.consommer Mapping message avec nom_q: {}", nom_q);
//                         sender
//                     },
//                     None => {
//                         match map_senders.get(domaine) {
//                             Some(sender) => {
//                                 debug!("domaines_messagerie.consommer Mapping message avec domaine: {}", domaine);
//                                 sender
//                             },
//                             None => {
//                                 error!("domaines_messagerie.consommer Message de queue ({}) et domaine ({}) inconnu, on le drop", nom_q, domaine);
//                                 continue  // On skip
//                             },
//                         }
//                     }
//                 };
//
//                 match sender.send(message).await {
//                     Ok(()) => (),
//                     Err(e) => {
//                         error!("domaines_messagerie.consommer Erreur consommer message {:?}", e)
//                     }
//                 }
//             },
//             TypeMessage::Certificat(_) => (),  // Rien a faire
//             TypeMessage::Regeneration => (),   // Rien a faire
//         }
//     }
//
//     info!("domaines_messagerie.consommer: Fin thread : {:?}", map_senders.keys());
// }

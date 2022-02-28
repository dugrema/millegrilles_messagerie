use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::sync::Arc;

use millegrilles_common_rust::tokio::sync::mpsc;
use millegrilles_common_rust::tokio::sync::mpsc::{Receiver, Sender};
use millegrilles_common_rust::mongodb::options::{AggregateOptions, CountOptions, FindOptions, Hint, UpdateOptions};

use log::{debug, error, info, warn};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::chiffrage::rechiffrer_asymetrique_multibase;
use millegrilles_common_rust::chiffrage_cle::requete_charger_cles;
use millegrilles_common_rust::constantes::{Securite, SECURITE_2_PRIVE};
use millegrilles_common_rust::constantes::Securite::{L1Public, L2Prive};
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::recepteur_messages::{MessageValideAction, TypeMessage};
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

/// Reception d'un evenement MQ de traitement de messages a poster
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
        where M: ValidateurX509 + GenerateurMessages + MongoDao
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
        where M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        // let idmgs = get_batch_idmgs(middleware, trigger).await?;
        // for idmg in idmgs {
        //     let batch = get_batch_messages(middleware, idmg.as_str()).await?;
        //     debug!("Traiter batch messages : {:?}", batch);
        //     traiter_batch_messages(middleware, idmg.as_str(), &batch).await?;
        // }

        traiter_messages_locaux(middleware, trigger).await;
        traiter_messages_tiers(middleware, trigger).await;

        // // Traitement messages locaux, traiter grande quantite puisque c'est local
        // {
        //     let batch = get_batch_messages(middleware, true, 1000).await?;
        //     debug!("Traiter batch messages locaux : {:?}", batch);
        //     for message in messages_outgoing {
        //         if let Err(e) = pousser_message_local(middleware, message).await {
        //             error!("traiter_batch_messages Erreur traitement pousser_message_local, message {} : {:?}", message.uuid_transaction, e);
        //         }
        //     }
        // }
        //
        // // Traitement messages tiers
        // {
        //     let batch = get_batch_messages(middleware, false, 10).await?;
        //     debug!("Traiter batch messages vers tiers : {:?}", batch);
        //     traiter_batch_messages(middleware, false, &batch).await?;
        // }

        Ok(())
    }
}

async fn traiter_messages_locaux<M>(middleware: &M, trigger: &MessagePompe)
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let batch = match get_batch_messages(middleware, true, 1000).await {
        Ok(b) => b,
        Err(e) => {
            error!("traiter_messages_locaux Erreur traitement pousser_message_local : {:?}", e);
            return
        }
    };

    debug!("Traiter batch messages locaux : {:?}", batch);
    for message in &batch {
        if let Err(e) = pousser_message_local(middleware, message).await {
            error!("traiter_messages_locaux Erreur traitement pousser_message_local, message {} : {:?}", message.uuid_transaction, e);
        }
    }
}

async fn traiter_messages_tiers<M>(middleware: &M, trigger: &MessagePompe)
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let batch = match get_batch_messages(middleware, false, 10).await {
        Ok(b) => b,
        Err(e) => {
            error!("traiter_messages_locaux Erreur traitement pousser_message_local : {:?}", e);
            return
        }
    };

    debug!("Traiter batch messages vers tiers : {:?}", batch);
    for message in &batch {
        if let Err(e) = pousser_message_vers_tiers(middleware, message).await {
            error!("traiter_batch_messages Erreur traitement pousser_message_vers_tiers message {} : {:?}",
                message.uuid_transaction, e);
        }
    }
}


// async fn get_batch_idmgs<M>(middleware: &M, trigger: &MessagePompe)
//     -> Result<Vec<String>, Box<dyn Error>>
//     where M: MongoDao
// {
//     let collection = middleware.get_collection(NOM_COLLECTION_OUTGOING_PROCESSING)?;
//
//     let mut filtre = doc! {};
//     if let Some(idmgs) = &trigger.idmgs {
//         filtre.insert("idmgs_unprocessed", doc! {"$all": idmgs});
//     }
//
//     let options = AggregateOptions::builder()
//         .build();
//
//     let pipeline = vec! [
//         // Match sur les idmgs specifies au besoin. Limiter matching si grande quantite en attente.
//         doc! {"$match": filtre},
//         // Expansion de tous les idmgs par message
//         doc! {"$unwind": {"path": "$idmgs_unprocessed"}},
//         // Grouper par date last_processed, permet d'aller chercher les plus vieux messages
//         doc! {"$group": {"_id": "$idmgs_unprocessed", "last_date": {"$min": "$last_processed"}}},
//         // Plus vieux en premier
//         doc! {"$sort": {"last_date": 1}},
//         // Mettre une limite dans la batch de retour
//         doc! {"$limit": 1},
//     ];
//     debug!("pompe_messages.get_batch_idmgs Pipeline idmgs a loader : {:?}", pipeline);
//
//     let mut curseur = collection.aggregate(pipeline, Some(options)).await?;
//     let mut resultat: Vec<String> = Vec::new();
//     while let Some(r) = curseur.next().await {
//         let doc = r?;
//         debug!("Result data : {:?}", doc);
//         let idmg = doc.get_str("_id")?;
//         resultat.push(idmg.into());
//     }
//
//     debug!("pompe_messages.get_batch_idmgs Resultat : {:?}", resultat);
//
//     Ok(resultat)
// }

// Retourne une batch de messages non traites pour un idmg.
// async fn get_batch_messages<M>(middleware: &M, idmg: &str)
async fn get_batch_messages<M>(middleware: &M, local: bool, limit: i64)
    -> Result<Vec<DocOutgointProcessing>, Box<dyn Error>>
    where M: ValidateurX509 + MongoDao
{
    debug!("pompe_messages.get_batch_messages");
    let collection = middleware.get_collection(NOM_COLLECTION_OUTGOING_PROCESSING)?;

    let idmg_local = middleware.idmg();
    let filtre = match local {
        true => {
            // Filtre sur idmg local
            let idmg_local = middleware.idmg();
            doc! { "idmgs_unprocessed": {"$all": [idmg_local]} }
        },
        false => doc! { "idmgs_unprocessed.1": {"$exists": true} }   // Au moins 1 idmg unprocessed
    };
    let sort = doc! { "last_processed": 1 };
    let options = FindOptions::builder()
        .sort(sort)
        .limit(limit)
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

// async fn traiter_batch_messages<M>(middleware: &M, local: bool, messages_outgoing: &Vec<DocOutgointProcessing>)
//     -> Result<(), Box<dyn Error>>
//     where M: GenerateurMessages + MongoDao
// {
//     debug!("pompe_messages.traiter_batch_messages Traiter batch {} messages", messages_outgoing.len());
//
//     if  {
//         debug!("Traitement messages pour idmg local : {}", idmg_traitement);
//         for message in messages_outgoing {
//             if let Err(e) = pousser_message_local(middleware, message).await {
//                 error!("traiter_batch_messages Erreur traitement pousser_message_local, message {} : {:?}", message.uuid_transaction, e);
//             }
//         }
//     } else {
//         for message in messages_outgoing {
//             if let Err(e) = pousser_message_vers_tiers(middleware, message).await {
//                 error!("traiter_batch_messages Erreur traitement pousser_message_vers_tiers idmg {}, message {} : {:?}",
//                     idmg_traitement, message.uuid_transaction, e);
//             }
//         }
//     };
//
//     Ok(())
// }

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

    // Extraire la liste des destinataires pour le IDMG a traiter (par mapping adresses)
    let destinataires = {
        let mut destinataires = mapper_destinataires(message, mapping);
        destinataires.into_iter().map(|d| d.destinataire).collect::<Vec<String>>()
    };

    // Charger transaction message mappee via serde
    let (message_a_transmettre, _) = charger_message(middleware, uuid_transaction).await?;

    // Emettre commande recevoir
    let commande = CommandeRecevoirPost{ message: message_a_transmettre, destinataires: destinataires.clone(), };
    let routage = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_RECEVOIR)
        .exchanges(vec![Securite::L2Prive])
        .build();

    // TODO - Mettre pompe sur sa propre Q, blocking true
    middleware.transmettre_commande(routage, &commande, false).await?;
    // debug!("Reponse commande message local : {:?}", reponse);

    // TODO - Fix verif confirmation. Ici on assume un succes
    //marquer_outgoing_resultat(middleware, uuid_transaction, &destinataires, true, 201).await?;

    Ok(())
}

/// Mapper les destinataires pour un message
fn mapper_destinataires(message: &DocOutgointProcessing, mapping: &DocMappingIdmg) -> Vec<DocDestinataire> {
    let mut destinataires = Vec::new();

    // Identifier destinataires qui correspondent au IDMG via DNS
    if let Some(mapping_dns) = mapping.dns.as_ref() {
        if let Some(d) = message.destinataires.as_ref() {
            for dest in d {
                if let Some(dns_destinataire) = dest.dns.as_ref() {
                    if mapping_dns.contains(dns_destinataire) {
                        if let Some(u) = dest.user.as_ref() {
                            // destinataires.push(u.clone());
                            destinataires.push(dest.to_owned());
                        }
                    }
                }
            }
        }
    }

    debug!("Mapping destinataires pour message {} : {:?}", message.uuid_transaction, destinataires);
    destinataires
}

async fn charger_message<M>(middleware: &M, uuid_transaction: &str) -> Result<(Map<String, Value>, CommandePoster), String>
    where M: MongoDao
{
    let collection_transactions = middleware.get_collection(NOM_COLLECTION_TRANSACTIONS)?;
    let filtre_transaction = doc! { "en-tete.uuid_transaction": uuid_transaction };
    let doc_message = match collection_transactions.find_one(filtre_transaction, None).await {
        Ok(d) => match d {
            Some(d) => Ok(d),
            None => Err(format!("pompe_messages.charger_message Transaction pour message {} introuvable", uuid_transaction))
        },
        Err(e) => Err(format!("pompe_messages.charger_message Erreur chargement transaction message : {:?}", e))
    }?;

    // Preparer message a transmettre. Enlever elements
    debug!("Message a transmettre : {:?}", doc_message);
    let message_mappe: CommandePoster = match convertir_bson_deserializable(doc_message.clone()) {
        Ok(m) => Ok(m),
        Err(e) => Err(format!("pompe_message.charger_message Erreur mapping message -> CommandePoster : {:?}", e))
    }?;

    let commande: CommandeRecevoirPost = match convertir_bson_deserializable(doc_message) {
        Ok(c) => Ok(c),
        Err(e) => Err(format!("pompe_messages.charger_message Erreur chargement transaction message : {:?}", e))
    }?;

    let mut val_message = commande.message;
    let mut keys_to_remove = Vec::new();
    for key in val_message.keys() {
        if key.starts_with("_") && key != "_signature" && key != "_bcc" {
            keys_to_remove.push(key.to_owned());
        }
    }
    for key in keys_to_remove {
        val_message.remove(key.as_str());
    }

    debug!("Message mappe : {:?}", val_message);
    Ok((val_message, message_mappe))
}

pub async fn marquer_outgoing_resultat<M>(middleware: &M, uuid_message: &str, idmg: &str, destinataires: &Vec<String>, processed: bool, result_code: u32)
                                          -> Result<(), String>
    where M: GenerateurMessages + MongoDao
{
    // let idmg_local = middleware.get_enveloppe_privee().idmg()?;
    debug!("Marquer idmg {} comme pousse pour message {}", idmg, uuid_message);

    // Marquer process comme succes pour reception sur chaque usager
    let collection_outgoing_processing = middleware.get_collection(NOM_COLLECTION_OUTGOING_PROCESSING)?;
    let filtre_outgoing = doc! { CHAMP_UUID_MESSAGE: uuid_message };
    let array_filters = vec! [
        doc! {"dest.destinataire": {"$in": destinataires }}
    ];
    let options = UpdateOptions::builder()
        .array_filters(array_filters.clone())
        .build();

    let mut ops = doc! {
        // "$pull": {"idmgs_unprocessed": &idmg_local},
        "$set": {
            "destinataires.$[dest].processed": processed,
            "destinataires.$[dest].result": result_code,
        },
        "$currentDate": {"last_processed": true}
    };
    if processed {
        ops.insert("$pull", doc!{"idmgs_unprocessed": &idmg});
    } else {
        // Incrementer retry count
        todo!("Incrementer retry count");
    }

    debug!("marquer_outgoing_resultat Filtre maj outgoing : {:?}, ops: {:?}, array_filters : {:?}", filtre_outgoing, ops, array_filters);
    match collection_outgoing_processing.update_one(filtre_outgoing, ops, Some(options)).await {
        Ok(resultat) => {
            debug!("marquer_outgoing_resultat Resultat marquer idmg {} comme pousse pour message {} : {:?}", idmg, uuid_message, resultat);
            Ok(())
        },
        Err(e) => Err(format!("pompe_messages.marquer_outgoing_resultat Erreur sauvegarde transaction, conversion : {:?}", e))
    }
}

async fn pousser_message_vers_tiers<M>(middleware: &M, message: &DocOutgointProcessing) -> Result<(), Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("Pousser message : {:?}", message);
    let uuid_transaction = message.uuid_transaction.as_str();
    let uuid_message = message.uuid_message.as_str();

    let idmg_local = middleware.idmg();

    // Charger transaction message mappee via serde
    let (message_a_transmettre, message_mappe) = charger_message(middleware, uuid_transaction).await?;

    // Recuperer cle du message
    let hachage_bytes = vec![message_mappe.message.hachage_bytes.clone()];
    let cle_message = requete_charger_cles(middleware, &hachage_bytes).await?;
    debug!("Recu cle message rechiffree : {:?}", cle_message);
    let cle_message_info = match &cle_message.cles {
        Some(c) => {
            match c.get(message_mappe.message.hachage_bytes.as_str()) {
                Some(c) => Ok(c),
                None => Err(format!("pompe_messages.pousser_message_vers_tiers Cle manquante dans reponse MaitreDesCles pour message {}", uuid_message))
            }
        },
        None => Err(format!("pompe_messages.pousser_message_vers_tiers Cle manquante pour message {}", uuid_message))
    }?;
    let cle_message_str = cle_message_info.cle.as_str();
    let enveloppe_privee = middleware.get_enveloppe_privee();
    let cle_privee = enveloppe_privee.cle_privee();

    let mapping: Vec<IdmgMappingDestinataires> = {
        let mut mapping = Vec::new();
        match message.idmgs_mapping.as_ref() {
            Some(mappings) => {
                let idmgs_unprocessed = match &message.idmgs_unprocessed {
                    Some(i) => i,
                    None => {
                        info!("pousser_message_vers_tiers Traitement d'un message ({}) avec aucuns idmgs unprocessed, ignorer.", uuid_transaction);
                        return Ok(())
                    }  // Rien a faire
                };

                // Faire liste des idmgs qui ne sont pas encore traites
                let mut set_idmgs = HashSet::new();
                for idmg in mappings.keys() {
                    if idmg == idmg_local { continue; } // Skip local
                    if idmgs_unprocessed.contains(idmg) {
                        set_idmgs.insert(idmg.clone());
                    }
                }

                // Recuperer mapping de l'application messagerie pour chaque idmg
                let routage_requete = RoutageMessageAction::builder("CoreTopologie", "applicationsTiers")
                    .exchanges(vec![L2Prive])
                    .build();
                let requete = json!({"idmgs": &set_idmgs, "application": "messagerie"});
                let fiches_applications: ReponseFichesApplications  = match middleware.transmettre_requete(routage_requete, &requete).await? {
                    TypeMessage::Valide(r) => {
                        debug!("pousser_message_vers_tiers Reponse applications : {:?}", r);
                        Ok(r.message.parsed.map_contenu(None)?)
                    },
                    _ => Err(format!("pompe_messages.pousser_message_vers_tiers Requete applicationsTiers, reponse de mauvais type"))
                }?;
                debug!("pousser_message_vers_tiers Reponse applications mappees : {:?}", fiches_applications);

                for fiche in fiches_applications.fiches {
                    let idmg = fiche.idmg.as_str();
                    let doc_mapping_idmg = match mappings.get(idmg) {
                        Some(d) => d,
                        None => continue  // Rien a faire
                    };

                    // Rechiffrer la cle du message
                    let certs_chiffrage = match &fiche.chiffrage {
                        Some(c) => c,
                        None => {
                            info!("Certificat de chiffrage manquant pour {}, on skip", idmg);
                            continue;
                        }
                    };
                    let ca_pem = match &fiche.ca {
                        Some(c) => c,
                        None => {
                            info!("Certificat CA manquant pour {}, on skip", idmg);
                            continue
                        }
                    };

                    let mut cles_rechiffrees = HashMap::new();
                    for cert_chiffrage in certs_chiffrage {
                        let cert = middleware.charger_enveloppe(
                            cert_chiffrage, None, Some(ca_pem.as_str())).await?;
                        let fingerprint = cert.fingerprint.clone();
                        let cle_publique = &cert.cle_publique;
                        let cle_rechiffree = match rechiffrer_asymetrique_multibase(
                            cle_privee, cle_publique, cle_message_str) {
                            Ok(k) => k,
                            Err(e) => {
                                error!("Erreur rechiffrage cle message {} pour idmg {}", uuid_message, idmg);
                                continue
                            }
                        };
                        cles_rechiffrees.insert(fingerprint, cle_rechiffree);
                    }

                    debug!("Cles rechiffrees pour idmg {}: {:?}", idmg, cles_rechiffrees);

                    let destinataires = {
                        let mut destinataires = mapper_destinataires(message, doc_mapping_idmg);
                        destinataires.into_iter().map(|d| d.destinataire).collect::<Vec<String>>()
                    };

                    let mapping_idmg = IdmgMappingDestinataires {
                        idmg: idmg.to_owned(),
                        mapping: doc_mapping_idmg.to_owned(),
                        destinataires,
                        fiche,
                        cles: cles_rechiffrees,
                    };

                    mapping.push(mapping_idmg);
                }

                // for (idmg, doc_mapping_idmg) in mappings.iter() {
                //     if idmg == idmg_local { continue; } // Skip local
                //
                //     let destinataires = {
                //         let mut destinataires = mapper_destinataires(message, doc_mapping_idmg);
                //         destinataires.into_iter().map(|d| d.destinataire).collect::<Vec<String>>()
                //     };
                //
                //     let mut mapping_idmg = IdmgMappingDestinataires {
                //         idmg: idmg.clone(),
                //         mapping: doc_mapping_idmg.to_owned(),
                //         destinataires,
                //     };
                //
                //     mapping.push(mapping_idmg);
                // }
            },
            None => Err(format!("pompe_message.pousser_message_vers_tiers Aucun mapping tiers"))?
        }
        mapping
    };

    // Emettre commande recevoir
    let commande = CommandePostmasterPoster{
        message: message_a_transmettre,
        destinations: mapping
    };
    debug!("pousser_message_vers_tiers Pousser message vers tiers {:?}", commande);

    let routage = RoutageMessageAction::builder("postmaster", "poster")
        .exchanges(vec![L1Public])
        .build();
    middleware.transmettre_commande(routage, &commande, false).await?;

    // TODO Fix marquer traitement apres upload
    warn!{"Marquer message pousse - TODO fix, simulation seulement"};
    for destination in &commande.destinations {
        let idmg_traitement = destination.idmg.as_str();
        let destinataires = &destination.destinataires;
        marquer_outgoing_resultat(middleware, uuid_message, idmg_traitement, &destinataires, true, 500).await?;
    }

    Ok(())
}
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::sync::Arc;

use millegrilles_common_rust::tokio::sync::mpsc;
use millegrilles_common_rust::tokio::sync::mpsc::{Receiver, Sender};
use millegrilles_common_rust::mongodb::options::{AggregateOptions, CountOptions, FindOneAndUpdateOptions, FindOptions, Hint, UpdateOptions};

use log::{debug, error, info, warn};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::chiffrage::rechiffrer_asymetrique_multibase;
use millegrilles_common_rust::chiffrage_cle::requete_charger_cles;
use millegrilles_common_rust::chrono::{Duration, Utc};
use millegrilles_common_rust::constantes::{CHAMP_MODIFICATION, Securite, SECURITE_2_PRIVE};
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
use crate::transactions::emettre_requete_resolve;

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
        traiter_dns_unresolved(middleware, trigger).await;
        traiter_messages_locaux(middleware, trigger).await;
        traiter_messages_tiers(middleware, trigger).await;
        expirer_messages(middleware, trigger).await;
        Ok(())
    }
}

async fn traiter_dns_unresolved<M>(middleware: &M, trigger: &MessagePompe)
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("traiter_dns_unresolved");

    let mut curseur = {
        let filtre = doc! { "dns_unresolved.1": {"$exists": true} };

        let limit = 1000;
        let sort = doc! { "created": 1 };
        let options = FindOptions::builder().sort(sort).limit(limit).build();

        let collection = match middleware.get_collection(NOM_COLLECTION_OUTGOING_PROCESSING) {
            Ok(c) => c,
            Err(e) => {
                error!("Erreur preparation collection {} : {:?}", NOM_COLLECTION_OUTGOING_PROCESSING, e);
                return
            }
        };

        match collection.find(filtre, Some(options)).await {
            Ok(c) => c,
            Err(e) => {
                error!("traiter_dns_unresolved Erreur requete mongodb : {:?}", e);
                return
            }
        }
    };

    let mut resultat: Vec<DocOutgointProcessing> = Vec::new();
    while let Some(r) = curseur.next().await {
        let message_outgoing: DocOutgointProcessing = match r {
            Ok(d) => {
                match convertir_bson_deserializable(d) {
                    Ok(m) => m,
                    Err(e) => {
                        error!("traiter_dns_unresolved Erreur mapping DocOutgointProcessing : {:?}", e);
                        continue
                    }
                }
            },
            Err(e) => {
                error!("traiter_dns_unresolved Erreur lecture curseur : {:?}", e);
                break  // Skip reste du curseur
            }
        };

        let uuid_transaction = message_outgoing.uuid_transaction.as_str();
        match message_outgoing.dns_unresolved.as_ref() {
            Some(dns) => {
                debug!("Nouvelle tentative de resolve pour message uuid_transaction:{}, DNS : {:?}", uuid_transaction, dns);
                match emettre_requete_resolve(middleware, uuid_transaction, &dns).await {
                    Ok(()) => (),
                    Err(e) => {
                        error!("Erreur emission requete resolve pour message uuid_transaction:{}, DNS : {:?}, err: {:?}", uuid_transaction, dns, e);
                    }
                }
            },
            None => ()
        }
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
    match traiter_messages_tiers_work(middleware, trigger).await {
        Ok(()) => (),
        Err(e) => {
            error!("traiter_messages_tiers Erreur traitement message : {:?}", e);
        }
    }
}

async fn traiter_messages_tiers_work<M>(middleware: &M, trigger: &MessagePompe)
    -> Result<(), Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let batch = get_batch_uuid_transactions(middleware, trigger).await?;
    debug!("Traiter batch messages vers tiers : {:?}", batch);

    let filtre = doc! {"uuid_transaction": {"$in": batch}};
    let collection = middleware.get_collection(NOM_COLLECTION_OUTGOING_PROCESSING)?;
    let mut curseur = collection.find(filtre, None).await?;
    while let Some(r) = curseur.next().await {
        let doc = r?;
        debug!("traiter_messages_tiers_work Result data : {:?}", doc);
        let message_outgoing: DocOutgointProcessing = match convertir_bson_deserializable(doc) {
            Ok(m) => m,
            Err(e) => {
                error!("traiter_messages_tiers_work Erreur mapping message {:?}", e);
                continue
            }
        };
        if let Err(e) = pousser_message_vers_tiers(middleware, &message_outgoing).await {
            error!("traiter_batch_messages Erreur traitement pousser_message_vers_tiers message {} : {:?}",
                message_outgoing.uuid_transaction, e);
        }
    }

    Ok(())
}

async fn expirer_messages<M>(middleware: &M, trigger: &MessagePompe)
    where M: MongoDao + GenerateurMessages
{
    debug!("expirer_messages");
    if let Err(e) = expirer_message_resolve(middleware, trigger).await {
        error!("expirer_messages Erreur traitement expirer messages unresolved : {:?}", e);
    }
    if let Err(e) = expirer_message_retry(middleware, trigger).await {
        error!("expirer_messages Erreur traitement expirer messages retry : {:?}", e);
    }
    if let Err(e) = marquer_messages_completes(middleware).await {
        error!("expirer_messages Erreur traitement marquer messages completes : {:?}", e);
    }
}

async fn expirer_message_resolve<M>(middleware: &M, trigger: &MessagePompe) -> Result<(), Box<dyn Error>>
    where M: MongoDao
{
    // Expirer DNS unresolved pour messages crees il y a plus de 30 minutes
    // Renommer dns_unresolved a dns_failure
    let ts_expire = Utc::now() - Duration::minutes(30);
    let filtre = doc! {
        "created": {"$lt": ts_expire},
        "dns_unresolved.0": {"$exists": true}
    };
    let ops = doc! {
        "$rename": {"dns_unresolved": "dns_failure"},
        "$currentDate": {CHAMP_LAST_PROCESSED: true},
    };

    let collection = middleware.get_collection(NOM_COLLECTION_OUTGOING_PROCESSING)?;
    let result = collection.update_many(filtre, ops, None).await?;
    debug!("expirer_message_work Resultat expirations : {:?}", result);

    Ok(())
}

// Retourne une batch de messages non traites pour un idmg.
// async fn get_batch_messages<M>(middleware: &M, idmg: &str)
async fn get_batch_messages<M>(middleware: &M, local: bool, limit: i64)
    -> Result<Vec<DocOutgointProcessing>, Box<dyn Error>>
    where M: ValidateurX509 + MongoDao
{
    debug!("pompe_messages.get_batch_messages");
    let collection = middleware.get_collection(NOM_COLLECTION_OUTGOING_PROCESSING)?;

    let ts_courant = Utc::now().timestamp();

    let idmg_local = middleware.idmg();
    let filtre = match local {
        true => {
            // Filtre sur idmg local
            let idmg_local = middleware.idmg();
            doc! { "idmgs_unprocessed": {"$all": [idmg_local]} }
        },
        false => doc! { "idmgs_unprocessed.1": {"$exists": true} }   // Au moins 1 idmg unprocessed
    };
    let sort = doc! { CHAMP_LAST_PROCESSED: 1 };
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

/// Pousse des messages locaux. Transfere le contenu dans la reception de chaque destinataire.
async fn pousser_message_local<M>(middleware: &M, message: &DocOutgointProcessing) -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + MongoDao
{
    debug!("Pousser message : {:?}", message);
    let uuid_transaction = message.uuid_transaction.as_str();

    // Mapping idmg local
    let idmg_local = middleware.get_enveloppe_privee().idmg()?;

    // Incrementer compteur, mettre next push a 15 minutes (en cas d'echec)
    incrementer_push(middleware, idmg_local.as_str(), uuid_transaction).await?;

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
    where M: ValidateurX509 + MongoDao + GenerateurMessages
{
    debug!("Marquer idmg {} comme pousse pour message {}", idmg, uuid_message);

    // Marquer process comme succes pour reception sur chaque usager
    let collection_outgoing_processing = middleware.get_collection(NOM_COLLECTION_OUTGOING_PROCESSING)?;
    let filtre_outgoing = doc! { CHAMP_UUID_MESSAGE: uuid_message };

    let array_filters = vec! [
        doc! {"dest.destinataire": {"$in": destinataires }}
    ];
    let options = FindOneAndUpdateOptions::builder()
        .array_filters(array_filters.clone())
        .build();

    let mut set_ops = doc!{
        format!("idmgs_mapping.{}.last_result_code", &idmg): result_code,
        "destinataires.$[dest].processed": processed,
        "destinataires.$[dest].result": result_code,
    };

    if ! processed {
        let next_push = (Utc::now() + Duration::minutes(5)).timestamp();
        set_ops.insert(format!("idmgs_mapping.{}.next_push_time", idmg), next_push);
    }

    let mut ops = doc! {
        "$set": set_ops,
        "$currentDate": {"last_processed": true}
    };

    if processed {
        ops.insert("$pull", doc!{"idmgs_unprocessed": &idmg});
        ops.insert("$unset", doc!{ format!("idmgs_mapping.{}.next_push_time", idmg): true });
    }

    debug!("marquer_outgoing_resultat Filtre maj outgoing : {:?}, ops: {:?}, array_filters : {:?}", filtre_outgoing, ops, array_filters);
    let doc_outgoing = match collection_outgoing_processing.find_one_and_update(filtre_outgoing.clone(), ops, Some(options)).await {
        Ok(resultat) => {
            debug!("marquer_outgoing_resultat Resultat marquer idmg {} comme pousse pour message {} : {:?}", idmg, uuid_message, resultat);
            Ok(resultat)
        },
        Err(e) => Err(format!("pompe_messages.marquer_outgoing_resultat Erreur sauvegarde transaction, conversion : {:?}", e))
    }?;

    let idmg_local = middleware.idmg();

    if idmg != idmg_local {
        if let Some(d) = doc_outgoing {
            let doc_mappe: DocOutgointProcessing = match convertir_bson_deserializable(d) {
                Ok(d) => Ok(d),
                Err(e) => Err(format!("pompe_messages.marquer_outgoing_resultat Erreur conversion DocOutgoingProcessing : {:?}", e))
            }?;
            if let Some(a) = doc_mappe.attachments {
                // Ajouter attachments au mapping du idmg pour transfert
                let ops = doc! {
                    "$set": {format!("idmgs_mapping.{}.attachments_restants", idmg): &a},
                    "$addToSet": {"idmgs_attachments_unprocessed": &idmg},
                };
                match collection_outgoing_processing.update_one(filtre_outgoing, ops, None).await {
                    Ok(_r) => Ok(()),
                    Err(e) => Err(format!("pompe_messages.marquer_outgoing_resultat Erreur update message pour upload attachments : {:?}", e))
                }?;

                // TODO Emettre trigger pour uploader les fichiers
                let commande = CommandePousserAttachments {
                    uuid_message: uuid_message.into(),
                    idmg_destination: idmg.into(),
                };
                let routage = RoutageMessageAction::builder(DOMAINE_POSTMASTER, "pousserAttachment")
                    .exchanges(vec![Securite::L1Public])
                    .build();
                middleware.transmettre_commande(routage, &commande, false).await?;
            }
        }
    }

    Ok(())
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

    // Charger certificat utilise dans le message
    let certificat_message: Vec<String> = {
        let fingerprint = message_mappe.message.fingerprint_certificat.as_str();
        match middleware.get_certificat(fingerprint).await {
            Some(c) => Ok(c.get_pem_vec().iter().map(|p| p.pem.clone()).collect()),
            None => Err(format!("pompe_messages.pousser_message_vers_tiers Certificat {} manquant pour message {}", fingerprint, uuid_message))
        }
    }?;

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

    let ts_courant = Utc::now();

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
                let requete = json!({"idmgs": &set_idmgs, "application": "messagerie_web"});
                debug!("pousser_message_vers_tiers Resolve idmgs avec CoreTopologie: {:?}", requete);
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

                    // Incrementer compteur, mettre next push a 15 minutes (en cas d'echec)
                    incrementer_push(middleware, idmg, uuid_transaction).await?;

                    let doc_mapping_idmg = match mappings.get(idmg) {
                        Some(d) => d,
                        None => continue  // Rien a faire
                    };

                    // Verifier si on doit attendre
                    match doc_mapping_idmg.next_push_time {
                        Some(t) => {
                            if t > ts_courant {
                                debug!("Skip {} pour {}, on doit attendre l'expiration de next_push_time a {:?}", uuid_transaction, idmg, t);
                                continue
                            }
                        },
                        None => ()
                    }

                    // Rechiffrer la cle du message
                    let mut certs_chiffrage = match fiche.chiffrage.clone() {
                        Some(c) => c,
                        None => {
                            info!("Certificat de chiffrage manquant pour {}, on skip", idmg);
                            continue;
                        }
                    };
                    let ca_pem = match &fiche.ca {
                        Some(c) => {
                            // Injecter dans la liste des certs_chiffrage (cle de millegrille)
                            certs_chiffrage.push(vec![c.clone()]);
                            c
                        },
                        None => {
                            info!("Certificat CA manquant pour {}, on skip", idmg);
                            continue
                        }
                    };

                    let mut cles_rechiffrees = HashMap::new();
                    for cert_chiffrage in &certs_chiffrage {
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

            },
            None => Err(format!("pompe_message.pousser_message_vers_tiers Aucun mapping tiers"))?
        }
        mapping
    };

    // Emettre commande recevoir
    let commande = CommandePostmasterPoster{
        message: message_a_transmettre,
        destinations: mapping,
        cle_info: cle_message_info.clone().into(),
        certificat_message,
        certificat_millegrille: middleware.ca_pem().into(),
    };
    debug!("pousser_message_vers_tiers Pousser message vers tiers {:?}", commande);

    let routage = RoutageMessageAction::builder(DOMAINE_POSTMASTER, "poster")
        .exchanges(vec![L1Public])
        .build();
    middleware.transmettre_commande(routage, &commande, false).await?;

    // TODO Fix marquer traitement apres upload
    // warn!{"Marquer message pousse - TODO fix, simulation seulement"};
    // for destination in &commande.destinations {
    //     let idmg_traitement = destination.idmg.as_str();
    //     let destinataires = &destination.destinataires;
    //     marquer_outgoing_resultat(middleware, uuid_message, idmg_traitement, &destinataires, true, 500).await?;
    // }

    Ok(())
}

async fn incrementer_push<M>(middleware: &M, idmg: &str, uuid_transaction: &str) -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + MongoDao
{
    let next_push = (Utc::now() + Duration::minutes(15)).timestamp();
    let ops = doc!{
        "$set": {
            format!("idmgs_mapping.{}.next_push_time", idmg): next_push,
        },
        "$inc": {
            format!("idmgs_mapping.{}.push_count", idmg): 1,
        },
        "$currentDate": {"last_processed": true}
    };
    let filtre = doc!{ "uuid_transaction": uuid_transaction };
    let collection = middleware.get_collection(NOM_COLLECTION_OUTGOING_PROCESSING)?;
    collection.update_one(filtre, ops, None).await?;

    Ok(())
}

async fn get_batch_uuid_transactions<M>(middleware: &M, trigger: &MessagePompe)
    -> Result<Vec<String>, Box<dyn Error>>
    where M: MongoDao
{
    debug!("get_batch_uuid_transactions");

    let limit = 10;

    let collection = middleware.get_collection(NOM_COLLECTION_OUTGOING_PROCESSING)?;

    let mut filtre = match &trigger.idmgs {
        Some(idmgs) => {
            // Utiliser la liste de IDMGs fournie
            doc! {"idmgs_unprocessed": {"$all": idmgs}}
        },
        None => {
            // Prendre tous les messages avec au moins 1 idmg unprocessed
            doc! {"idmgs_unprocessed.0": {"$exists": true}}
        }
    };

    let options = AggregateOptions::builder()
        .build();

    let ts_courant = Utc::now().timestamp();

    let pipeline = vec! [
        // Match sur les idmgs specifies au besoin. Limiter matching si grande quantite en attente.
        doc! {"$match": filtre},
        doc! {"$limit": limit * 20},  // Limite quantite max a traiter (safety)

        // Expansion de tous les idmgs par message
        // Convertir idmgs_mapping en array, et faire unwind. Expose next_push_time.
        doc! {"$project": {
            "uuid_transaction": 1,
            // "last_processed": true,
            "idmgs_mapping": {"$objectToArray": "$idmgs_mapping"}
        }},
        doc! { "$unwind": {"path": "$idmgs_mapping"} },
        doc! { "$match": {"idmgs_mapping.v.next_push_time": {"$lte": ts_courant}} },

        // // Grouper par date last_processed, permet d'aller chercher les plus vieux messages
        doc! {"$group": {"_id": "$uuid_transaction", "next_date": {"$min": "$idmgs_mapping.v.next_push_time"}}},

        // // Plus vieux en premier
        doc! {"$sort": {"next_date": 1}},

        // // Mettre une limite dans la batch de retour
        doc! {"$limit": limit},
    ];
    debug!("get_batch_uuid_transactions Pipeline idmgs a loader : {:?}", pipeline);

    let mut curseur = collection.aggregate(pipeline, Some(options)).await?;
    let mut resultat: Vec<String> = Vec::new();
    while let Some(r) = curseur.next().await {
        let doc = r?;
        debug!("get_batch_uuid_transactions Result data : {:?}", doc);
        let uuid_transaction = doc.get_str("_id")?;
        resultat.push(uuid_transaction.into());
    }

    debug!("get_batch_uuid_transactions Resultat : {:?}", resultat);

    Ok(resultat)
}

async fn expirer_message_retry<M>(middleware: &M, trigger: &MessagePompe) -> Result<(), Box<dyn Error>>
    where M: MongoDao
{
    const RETRY_LIMIT: i32 = 3;

    let options = AggregateOptions::builder().build();

    let pipeline = vec! [
        // Match sur les idmgs specifies au besoin. Limiter matching si grande quantite en attente.
        doc! {"$match": {"idmgs_unprocessed.0": {"$exists": true}} },
        doc! {"$limit": 1000},  // Limite quantite max a traiter (safety)

        // Expansion de tous les idmgs par message
        // Convertir idmgs_mapping en array, et faire unwind. Expose next_push_time.
        doc! {"$project": {
            "uuid_transaction": 1,
            "idmgs_mapping": {"$objectToArray": "$idmgs_mapping"}
        }},
        doc! { "$unwind": {"path": "$idmgs_mapping"} },

        // Plus vieux en premier
        doc! {"$match": {"idmgs_mapping.v.push_count": {"$gte": RETRY_LIMIT} }},

        doc! {"$project": {
            "uuid_transaction": 1,
            "idmg": "$idmgs_mapping.k",
            "push_count": "$idmgs_mapping.v.push_count",
        }},

        // Mettre une limite dans la batch de retour
        doc! {"$limit": 5000},
    ];
    debug!("expirer_message_retry Pipeline idmgs a invalider : {:?}", pipeline);

    let collection = middleware.get_collection(NOM_COLLECTION_OUTGOING_PROCESSING)?;
    let mut curseur = collection.aggregate(pipeline, Some(options)).await?;
    while let Some(r) = curseur.next().await {
        let doc = r?;
        debug!("expirer_message_retry Result a expirer : {:?}", doc);
        let uuid_transaction = doc.get_str("uuid_transaction")?;
        let idmg = doc.get_str("idmg")?;

        let filtre = doc! { "uuid_transaction": uuid_transaction };
        let ops = doc! {
            "$pull": {"idmgs_unprocessed": &idmg},
            "$unset": {format!("idmgs_mapping.{}.next_push_time", idmg): true}
        };

        collection.update_one(filtre, ops, None).await?;
    }

    Ok(())
}

pub async fn verifier_fin_transferts_attachments<M>(middleware: &M, doc_outgoing: &DocOutgointProcessing) -> Result<(), Box<dyn Error>>
    where M: MongoDao
{
    debug!("verifier_fin_transferts_attachments pour {:?}", doc_outgoing);
    let idmgs_processing = match &doc_outgoing.idmgs_attachments_unprocessed {
        Some(d) => d,
        None => return Ok(())  // Rien a faire
    };

    // Verifier s'il reste au moins un transfert pending/en_cours pour chaque idmg
    let mut idmgs_completes: Vec<String> = Vec::new();
    for idmg in idmgs_processing {
        if let Some(i) = &doc_outgoing.idmgs_mapping {
            if let Some(m) = i.get(idmg) {
                let len_restants = match &m.attachments_restants {
                    Some(a) => a.len(),
                    None => 0
                };
                let len_en_cours = match &m.attachments_en_cours {
                    Some(a) => a.len(),
                    None => 0
                };

                let total_attachments_incomplets = len_restants + len_en_cours;
                debug!("verifier_fin_transferts_attachments Nombre attachements incomplets: {}", total_attachments_incomplets);

                if total_attachments_incomplets == 0 {
                    idmgs_completes.push(idmg.into());
                }
            } else {
                warn!("verifier_fin_transferts_attachments idmgs_mapping pour {} n'existe pas dans {}, on le retire implicitement",
                    idmg, doc_outgoing.uuid_message);
                idmgs_completes.push(idmg.into());
            }
        } else {
            warn!("verifier_fin_transferts_attachments idmgs_mapping n'existe pas dans {}, on le retire implicitement",
                doc_outgoing.uuid_message);
            idmgs_completes.push(idmg.into());
        }
    }

    let filtre = doc! { CHAMP_UUID_MESSAGE: &doc_outgoing.uuid_message };
    let mut unset_ops = doc! {};
    // for idmg in idmgs_completes {
    //     unset_ops.insert(format!("idmgs_mapping.{}.attachments_restants", idmg), true);
    //     unset_ops.insert(format!("idmgs_mapping.{}.attachments_en_cours", idmg), true);
    // }
    let ops = doc! {
        // "$unset": unset_ops,
        "$pull": {"idmgs_attachments_unprocessed": {"$in": &idmgs_completes}},
        "$currentDate": {CHAMP_LAST_PROCESSED: true},
    };
    let collection = middleware.get_collection(NOM_COLLECTION_OUTGOING_PROCESSING)?;
    collection.update_one(filtre, ops, None).await?;

    Ok(())
}

async fn marquer_messages_completes<M>(middleware: &M) -> Result<(), Box<dyn Error>>
    where M: MongoDao + GenerateurMessages
{
    // Messages completes qui n'ont pas ete nettoyes
    let collection = middleware.get_collection(NOM_COLLECTION_OUTGOING_PROCESSING)?;

    let mut messages_completes = HashMap::new();
    {
        let filtre = doc! {
            "idmgs_unprocessed": {"$exists": true},
            "idmgs_unprocessed.0": {"$exists": false},
        };
        let mut curseur = collection.find(filtre, None).await?;
        while let Some(d) = curseur.next().await {
            let doc = d?;
            let doc_outgoing: DocOutgointProcessing = convertir_bson_deserializable(doc)?;
            let uuid_message = doc_outgoing.uuid_message.clone();
            let transaction = TransactionTransfertComplete {
                uuid_message: doc_outgoing.uuid_message,
                message_complete: Some(true),
                attachments_completes: None
            };
            messages_completes.insert(uuid_message, transaction);
            // middleware.soumettre_transaction(routage.clone(), &transaction, false).await?;
        }
    }

    {
        let filtre = doc! {
            "idmgs_attachments_unprocessed": {"$exists": true},
            "idmgs_attachments_unprocessed.0": {"$exists": false},
        };
        let mut curseur = collection.find(filtre, None).await?;
        while let Some(d) = curseur.next().await {
            let doc = d?;
            let doc_outgoing: DocOutgointProcessing = convertir_bson_deserializable(doc)?;
            let uuid_message = doc_outgoing.uuid_message.clone();
            match messages_completes.get_mut(uuid_message.as_str()) {
                Some(t) => {
                    t.attachments_completes = Some(true);
                },
                None => {
                    let t = TransactionTransfertComplete {
                        uuid_message: doc_outgoing.uuid_message,
                        message_complete: None,
                        attachments_completes: Some(true)
                    };
                    messages_completes.insert(uuid_message, t);
                }
            }
        }
    }

    let routage = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_TRANSFERT_COMPLETE)
        .exchanges(vec![Securite::L4Secure])
        .build();

    for transaction in messages_completes.values() {
        middleware.soumettre_transaction(routage.clone(), transaction, false).await?;
    }

    Ok(())
}
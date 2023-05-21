use std::collections::{BTreeMap, HashMap, HashSet};
use std::error::Error;
use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose};

use log::{debug, error, info, warn};
use millegrilles_common_rust::{multibase, serde_json, serde_json::json};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{Bson, doc, Document};
use millegrilles_common_rust::certificats::{EnveloppeCertificat, ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chiffrage::{ChiffrageFactory, CipherMgs, CleChiffrageHandler, CleSecrete, FormatChiffrage, MgsCipherKeys};
use millegrilles_common_rust::chiffrage_cle::CommandeSauvegarderCle;
use millegrilles_common_rust::chiffrage_ed25519::dechiffrer_asymmetrique_ed25519;
use millegrilles_common_rust::chrono::{DateTime, Utc, Duration};
use millegrilles_common_rust::common_messages::{DataChiffre, DataDechiffre, MessageReponse, TransactionRetirerSubscriptionWebpush};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageInterMillegrille, MessageMilleGrille, MessageSerialise};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction, sauvegarde_attachement_cle};
use millegrilles_common_rust::middleware::{ChiffrageFactoryTrait, sauvegarder_traiter_transaction, sauvegarder_traiter_transaction_serializable};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, MongoDao, verifier_erreur_duplication_mongo};
use millegrilles_common_rust::mongodb::Collection;
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, FindOptions, Hint, ReturnDocument, UpdateOptions};
use millegrilles_common_rust::multibase::Base;
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::{MessageValideAction, TypeMessage};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::Transaction;
use millegrilles_common_rust::verificateur::{ValidationOptions, VerificateurMessage};
use millegrilles_common_rust::openssl::pkey::{PKey, Private};
use millegrilles_common_rust::openssl::bn::BigNumContext;
use millegrilles_common_rust::openssl::nid::Nid;
use millegrilles_common_rust::openssl::ec::{EcGroup, EcKey, PointConversionForm};
use millegrilles_common_rust::dechiffrage::dechiffrer_documents;
use millegrilles_common_rust::messages_generiques::{CommandeCleRechiffree, CommandeDechiffrerCle, ConfirmationTransmission};
use millegrilles_common_rust::serde_json::Value;
use web_push::{ContentEncoding, PartialVapidSignatureBuilder, SubscriptionInfo, VapidSignatureBuilder, WebPushClient, WebPushMessageBuilder};

use crate::gestionnaire::GestionnaireMessagerie;
use crate::constantes::*;
use crate::transactions::*;
use crate::message_structs::*;
use crate::pompe_messages::{marquer_outgoing_resultat, verifier_fin_transferts_attachments};

const REQUETE_MAITREDESCLES_VERIFIER_PREUVE: &str = "verifierPreuve";
const WEBPUSH_TTL: u32 = 12 * 3600;

pub async fn consommer_commande<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage + ValidateurX509 + ChiffrageFactoryTrait
{
    debug!("consommer_commande : {:?}", &m.message);

    let user_id = m.get_user_id();
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);

    if role_prive && user_id.is_some() {
        // Ok, commande usager
    } else {
        match m.verifier_exchanges(vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure)) {
            true => Ok(()),
            false => {
                // Verifier si on a un certificat delegation globale
                match m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
                    true => Ok(()),
                    false => Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id)),
                }
            }
        }?;
    }

    match m.action.as_str() {
        // Commandes standard
        COMMANDE_CONFIRMER_TRANSMISSION => commande_confirmer_transmission(middleware, m, gestionnaire).await,
        COMMANDE_PROCHAIN_ATTACHMENT => commande_prochain_attachment(middleware, m, gestionnaire).await,
        COMMANDE_UPLOAD_ATTACHMENT => commande_upload_attachment(middleware, m).await,
        COMMANDE_FUUID_VERIFIER_EXISTANCE => commande_fuuid_verifier_existance(middleware, m).await,
        COMMANDE_CONSERVER_CLES_ATTACHMENTS => commande_conserver_cles_attachments(middleware, m, gestionnaire).await,
        COMMANDE_GENERER_CLEWEBPUSH_NOTIFICATIONS => generer_clewebpush_notifications(middleware, m, gestionnaire).await,
        COMMANDE_EMETTRE_NOTIFICATIONS_USAGER => emettre_notifications_usager(middleware, m, gestionnaire).await,
        COMMANDE_RECEVOIR_EXTERNE => commande_recevoir_externe(middleware, m, gestionnaire).await,

        // Transactions
        TRANSACTION_POSTER => commande_poster(middleware, m, gestionnaire).await,
        TRANSACTION_RECEVOIR => commande_recevoir(middleware, m, gestionnaire).await,
        TRANSACTION_INITIALISER_PROFIL => commande_initialiser_profil(middleware, m, gestionnaire).await,
        TRANSACTION_MAJ_CONTACT => commande_maj_contact(middleware, m, gestionnaire).await,
        TRANSACTION_LU => commande_lu(middleware, m, gestionnaire).await,
        TRANSACTION_SUPPRIMER_MESSAGES => commande_supprimer_message(middleware, m, gestionnaire).await,
        TRANSACTION_SUPPRIMER_CONTACTS => commande_supprimer_contacts(middleware, m, gestionnaire).await,
        TRANSACTION_CONSERVER_CONFIGURATION_NOTIFICATIONS => commande_conserver_configuration_notifications(middleware, m, gestionnaire).await,
        TRANSACTION_SAUVEGARDER_USAGER_CONFIG_NOTIFICATIONS => commande_sauvegarder_usager_config_notifications(middleware, m, gestionnaire).await,
        TRANSACTION_SAUVEGARDER_SUBSCRIPTION_WEBPUSH => commande_sauvegarder_subscription_webpush(middleware, m, gestionnaire).await,
        TRANSACTION_RETIRER_SUBSCRIPTION_WEBPUSH => commande_retirer_subscription_webpush(middleware, m, gestionnaire).await,
        TRANSACTION_NOTIFIER => commande_notifier(middleware, m, gestionnaire).await,

        // Commandes inconnues
        _ => Err(format!("core_backup.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, m.action))?,
    }
}

async fn commande_poster<M>(middleware: &M, mut m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509 + VerificateurMessage
{
    let attachements = m.message.parsed.attachements.take();

    debug!("commande_poster Consommer commande : {:?}", & m.message);
    let commande: CommandePoster = m.message.get_msg().map_contenu()?;
    debug!("Commande nouvelle versions parsed : {:?}", commande);

    let user_id = m.get_user_id();
    match m.verifier_exchanges(vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure)) {
        true => {
            // Compte systeme
        },
        false => {
            // Autorisation: Action usager avec compte prive ou delegation globale
            let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
            if role_prive && user_id.is_some() {
                // Ok
            } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
                // Ok
            } else {
                Err(format!("commandes.commande_poster: Commande autorisation invalide pour message {:?}", m.correlation_id))?
            }
        }
    }

    // Valider le message dans la commande poster. Reutiliser le certificat deja valide pour la commande.
    {
        let mut message_serialise = MessageSerialise::from_parsed(m.message.parsed.clone())?;
        message_serialise.certificat = m.message.certificat.clone();
        let resultat = middleware.verifier_message(&mut message_serialise, None)?;
        if resultat.valide() == false {
            Err(format!("commandes.commande_poster: Message dans la commande {:?} invalide : {:?}", m.correlation_id, resultat))?
        }
    }

    // Sauvegarer la cle
    match attachements {
        Some(mut attachements) => {
            match attachements.remove("cle") {
                Some(mut cle) => {
                    let mut cle_message: MessageMilleGrille = serde_json::from_value(cle)?;
                    let partition = match cle_message.attachements.take() {
                        Some(mut inner) => match inner.remove("partition") {
                            Some(inner) => match inner.as_str() {
                                Some(partition) => partition.to_owned(),
                                None => Err(format!("commandes.commande_poster: Erreur sauvegarde cle (pas string) pour message {:?}", m.correlation_id))?
                            },
                            None => Err(format!("commandes.commande_poster: Erreur sauvegarde cle (absente) pour message {:?}", m.correlation_id))?
                        },
                        None => Err(format!("commandes.commande_poster: Erreur sauvegarde cle (attachements cle absents) pour message {:?}", m.correlation_id))?
                    };
                    let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, COMMANDE_SAUVEGARDER_CLE)
                        .exchanges(vec![Securite::L3Protege])
                        .partition(partition)
                        .build();
                    debug!("commandes.commande_poster: Sauvegarder cle message aupres de {:?} : {:?}", routage, cle_message);
                    let reponse = middleware.emettre_message_millegrille(routage, true, TypeMessageOut::Commande, cle_message).await?;
                    if let Some(TypeMessage::Valide(reponse)) = reponse {
                        debug!("commandes.commande_poster Reponse sauvegarde cle : {:?}", reponse);
                        let resultat: MessageReponse = reponse.message.parsed.map_contenu()?;
                        if let Some(true) = resultat.ok {
                            // Ok
                            debug!("commandes.commande_poster Sauvegarde cle OK");
                        } else {
                            Err(format!("commandes.commande_poster: Erreur sauvegarde cle (ok==false) pour message {:?}", m.correlation_id))?
                        }
                    } else {
                        Err(format!("commandes.commande_poster: Erreur sauvegarde cle pour message {:?}", m.correlation_id))?
                    }
                },
                None => Err(format!("commandes.commande_poster: Cle manquante des attachements pour message {:?}", m.correlation_id))?
            }
        },
        None => Err(format!("commandes.commande_poster: Attachements vides (cle manquante) pour message {:?}", m.correlation_id))?
    }

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_recevoir<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509 + VerificateurMessage
{
    debug!("commandes.commande_recevoir Consommer commande : {:?}", & m.message);
    let mut commande: CommandeRecevoirPost = m.message.get_msg().map_contenu()?;
    debug!("commandes.commande_recevoir Commande nouvelle versions parsed : {:?}", commande);

    // let user_id = m.get_user_id();
    match m.verifier_exchanges(vec!(Securite::L2Prive, Securite::L3Protege, Securite::L4Secure)) {
        true => {
            // Compte systeme local, ok
        },
        false => {
            // // Autorisation: Action usager avec compte prive ou delegation globale
            // let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
            // if role_prive && user_id.is_some() {
            //     // Ok
            // } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
            //     // Ok
            // } else {
                Err(format!("commandes.commande_recevoir: Commande autorisation invalide pour message {:?}", m.correlation_id))?
            // }
        }
    }

    let mut message = MessageSerialise::from_parsed(commande.message)?;

    // Charger les certificats pour valider le message encapsule
    let est_local = message.parsed.origine == Some(middleware.get_enveloppe_signature().idmg()?);
    let certificat_millegrille = match est_local {
        true => None,  // Pas besoin de charger le certififcat CA local
        false => {
            // Charger le certificat CA distant
            match message.parsed.millegrille.clone() {
                Some(inner) => {
                    Some(middleware.charger_enveloppe(&vec![inner], None, None).await?)
                },
                None => Err(format!("commandes.commande_recevoir: Certificat CA absent du message encapsule tiers {:?}", m.correlation_id))?
            }
        }
    };
    let certificat_message = match message.parsed.certificat.as_ref() {
        Some(inner) => {
            let ca_pem = match message.parsed.millegrille.as_ref() {
                Some(inner) => Some(inner.as_str()),
                None => None
            };
            middleware.charger_enveloppe(inner, None, ca_pem).await?
        },
        None => {
            match middleware.get_certificat(message.parsed.pubkey.as_str()).await {
                Some(inner) => inner,
                None => {
                    error!("commandes.commande_recevoir: Certificat absent du message encapsule {:?}", m.correlation_id);
                    let reponse_erreur = json!({"ok": false, "err": "Certificat absent du message encapsule"});
                    return Ok(Some(middleware.formatter_reponse(&reponse_erreur, None)?));
                }
            }
        }
    };

    // Verifier le message encapsule
    message.certificat = Some(certificat_message);
    message.millegrille = certificat_millegrille;
    let resultat_verification = middleware.verifier_message(&mut message, None)?;
    match resultat_verification.valide() {
        true => debug!("commande_recevoir Message encapsule dans la commande recevoir est valide"),
        false => {
            error!("commandes.commande_recevoir: Message encapsule est invalide {:?} : {:?}", m.correlation_id, resultat_verification);
            let reponse_erreur = json!({"ok": false, "err": "Erreur validation message", "detail": format!("{:?}", resultat_verification)});
            return Ok(Some(middleware.formatter_reponse(&reponse_erreur, None)?));
        }
    }

    // Resolve users
    let destinataires = {
        let mut destinataires_user_id = Vec::new();
        let mut destinataires_adresse_user = Vec::new();
        for adresse in &commande.destinataires {
            debug!("Resolve destinataire {}", adresse);
            match AdresseMessagerie::new(adresse.as_str()) {
                Ok(a) => destinataires_adresse_user.push(a.user),
                Err(e) => info!("Erreur parsing adresse {}, on l'ignore", adresse)
            }
        }
        let requete_routage = RoutageMessageAction::builder("CoreMaitreDesComptes", "getUserIdParNomUsager")
            .exchanges(vec![Securite::L4Secure])
            .build();
        let requete = json!({"noms_usagers": destinataires_adresse_user});
        debug!("transaction_recevoir Requete {:?} pour user names : {:?}", requete_routage, requete);
        let reponse = middleware.transmettre_requete(requete_routage, &requete).await?;
        debug!("transaction_recevoir Reponse mapping users : {:?}", reponse);
        let reponse_mappee: ReponseUseridParNomUsager = match reponse {
            TypeMessage::Valide(m) => {
                match m.message.parsed.map_contenu() {
                    Ok(m) => m,
                    Err(e) => Err(format!("pompe_messages.transaction_recevoir Erreur mapping reponse requete noms usagers : {:?}", e))?
                }
            },
            _ => Err(format!("pompe_messages.transaction_recevoir Erreur mapping reponse requete noms usagers, mauvais type reponse"))?
        };

        for adresse in &commande.destinataires {
            debug!("Resolve destinataire {}", adresse);
            match AdresseMessagerie::new(adresse.as_str()) {
                Ok(a) => {
                    let user_id_option = reponse_mappee.usagers.get(a.user.as_str());
                    if let Some(uo) = user_id_option {
                        destinataires_user_id.push(DestinataireInfo{
                            adresse: Some(adresse.to_owned()),
                            user_id: uo.to_owned()
                        })
                    }
                },
                Err(e) => info!("Erreur parsing adresse {}, on l'ignore", adresse)
            }
        }

        destinataires_user_id
    };

    // if let Some(cle) = commande.cle.take() {
    if let Some(mut attachements) = message.parsed.attachements.take() {
        if let Some(cle) = attachements.remove("cle") {
            let cle: CommandeSauvegarderCle = serde_json::from_value(cle)?;
            debug!("Sauvegarder cle : {:?}", cle);
            if let Some(p) = cle.partition.as_ref() {
                let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, COMMANDE_SAUVEGARDER_CLE)
                    .exchanges(vec![Securite::L3Protege])
                    .partition(p.to_owned())
                    .build();
                let reponse = middleware.transmettre_commande(routage, &cle, true).await?;
                debug!("Reponse commande sauvegarder cle {:?}", reponse);
            } else {
                Err(format!("commandes.recevoir Erreur sauvegarde cle - partition n'est pas fournie"))?
            }
        }
    }

    // Cleanup, retirer certificat du message (stocke externe)
    message.parsed.retirer_certificats();

    let commande_maj = DocumentRecevoirPost {
        message: message.parsed,
        destinataires_user_id: destinataires,
        fuuids: commande.fuuids,
    };

    // Traiter la transaction
    //Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
    Ok(sauvegarder_traiter_transaction_serializable(
        middleware, &commande_maj, gestionnaire, DOMAINE_NOM, TRANSACTION_RECEVOIR).await?)
}

async fn commande_initialiser_profil<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509 + ChiffrageFactoryTrait + VerificateurMessage
{
    debug!("commandes.commande_initialiser_profil Consommer commande : {:?}", & m.message);
    let commande: CommandeInitialiserProfil = m.message.get_msg().map_contenu()?;
    debug!("commandes.commande_initialiser_profil Commande nouvelle versions parsed : {:?}", commande);

    let user_id = match m.get_user_id() {
        Some(u) => u,
        None => return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "userId manquant", "code": 403}), None)?))
    };
    // Autorisation: Action usager avec compte prive ou delegation globale
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    if role_prive {
        // Ok
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("commandes.commande_initialiser_profil: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    }

    let collection = middleware.get_collection(NOM_COLLECTION_PROFILS)?;
    let filtre = doc! {CHAMP_USER_ID: &user_id};
    let doc_profil = collection.find_one(filtre, None).await?;
    if doc_profil.is_some() {
        return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "profil existe deja", "code": 400}), None)?))
    }

    // Generer une nouvelle cle pour le profil de l'usager (chiffrer parametres, contacts, etc)
    let cle_profil = {
        let mut chiffreur = middleware.get_chiffrage_factory().get_chiffreur()?;
        let now = Utc::now().timestamp_nanos().to_le_bytes();
        let mut output = [0u8; 8];
        chiffreur.update(&now, &mut output)?;
        let (_, keys) = chiffreur.finalize(&mut [0u8; 25])?;
        let mut identificateurs = HashMap::new();
        identificateurs.insert("user_id".to_string(), user_id.clone());
        identificateurs.insert("type".to_string(), "profil".to_string());
        debug!("commande_initialiser_profil Hachage bytes {}", keys.hachage_bytes);
        let cle_profil = keys.get_commande_sauvegarder_cles(DOMAINE_NOM, None, identificateurs)?;
        let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, COMMANDE_SAUVEGARDER_CLE)
            .exchanges(vec![Securite::L4Secure])
            .build();
        debug!("commande_initialiser_profil Sauvegarder cle {:?}", cle_profil);
        if let Some(TypeMessage::Valide(reponse)) = middleware.transmettre_commande(routage, &cle_profil, true).await? {
            debug!("commande_initialiser_profil Sauvegarder cle resultat : {:?}", reponse);
            let valeur_reponse: MessageReponse = reponse.message.parsed.map_contenu()?;
            if let Some(true) = valeur_reponse.ok {
                // Ok
            } else {
                Err(format!("commandes.commande_initialiser_profil Erreur sauvegarder cle, reponse ok=false"))?;
            }
        } else {
            Err(format!("commandes.commande_initialiser_profil Erreur sauvegarder cle, aucune reponse/reponse invalide"))?;
        }
        cle_profil
    };

    // Generer nouvelle transaction
    let transaction = TransactionInitialiserProfil {
        user_id: user_id.clone(),
        adresse: commande.adresse,
        cle_ref_hachage_bytes: cle_profil.hachage_bytes
    };
    let transaction = middleware.formatter_message(
        MessageKind::Transaction, &transaction,
        Some(DOMAINE_NOM), Some(m.action.as_str()), None,
        None, false)?;
    let mut transaction = MessageValideAction::from_message_millegrille(
        transaction, TypeMessageOut::Transaction)?;

    // Conserver enveloppe pour validation
    transaction.message.set_certificat(middleware.get_enveloppe_signature().enveloppe.clone());

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, transaction, gestionnaire).await?)
}

async fn commande_maj_contact<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509 + VerificateurMessage,
{
    debug!("commandes.commande_maj_contact Consommer commande : {:?}", & m.message);
    let commande: Contact = m.message.get_msg().map_contenu()?;
    debug!("commandes.commande_maj_contact Commande nouvelle versions parsed : {:?}", commande);

    let user_id = match m.get_user_id() {
        Some(u) => u,
        None => return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "userId manquant", "code": 403}), None)?))
    };
    // Autorisation: Action usager avec compte prive ou delegation globale
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    if role_prive {
        // Ok
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("commandes.commande_initialiser_profil: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    }

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_lu<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509 + VerificateurMessage
{
    debug!("commandes.commande_lu Consommer commande : {:?}", & m.message);
    let commande: CommandeLu = m.message.get_msg().map_contenu()?;
    debug!("commandes.commande_lu Commande nouvelle versions parsed : {:?}", commande);

    let user_id = match m.get_user_id() {
        Some(u) => u,
        None => return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "userId manquant", "code": 403}), None)?))
    };

    // Autorisation: Action usager avec compte prive ou delegation globale
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    if role_prive {
        // Ok
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("commandes.commande_initialiser_profil: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    }

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_confirmer_transmission<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + MongoDao + GenerateurMessages
{
    debug!("commande_confirmer_transmission Consommer commande : {:?}", & m.message);
    let commande: ConfirmationTransmission = m.message.get_msg().map_contenu()?;
    debug!("commande_confirmer_transmission Commande parsed : {:?}", commande);

    let message_id = commande.message_id.as_str();
    let idmg = commande.idmg.as_str();

    // let destinataires = match commande.destinataires.as_ref() {
    //     Some(d) => {
    //         d.iter().map(|d| d.destinataire.clone()).collect()
    //     },
    //     None => Vec::new()
    // };

    let result_code = commande.code as u32;
    let processed = match &commande.code {
        200 | 201 | 202 | 404 => true,
        _ => false
    };

    marquer_outgoing_resultat(middleware, message_id, idmg, None, processed, Some(result_code)).await?;

    Ok(None)
}

async fn commande_prochain_attachment<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + MongoDao + GenerateurMessages
{
    debug!("commande_confirmer_transmission Consommer commande : {:?}", & m.message);
    let commande: CommandeProchainAttachment = m.message.get_msg().map_contenu()?;
    debug!("commande_confirmer_transmission Commande parsed : {:?}", commande);

    let uuid_message = commande.message_id.as_str();
    let idmg = commande.idmg_destination.as_str();

    let filtre = doc! { CHAMP_UUID_MESSAGE: uuid_message };
    let collection = middleware.get_collection(NOM_COLLECTION_OUTGOING_PROCESSING)?;
    let doc_outgoing: DocOutgointProcessing = {
        let doc_outgoing = collection.find_one(filtre.clone(), None).await?;
        match doc_outgoing {
            Some(d) => convertir_bson_deserializable(d)?,
            None => {
                warn!("commande_prochain_attachment Aucun message correspondant trouve (uuid_message: {})", uuid_message);
                return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Aucun message correspondant"}), None)?))
            }
        }
    };

    // Determiner s'il reste des attachments a uploader
    let mapping = match &doc_outgoing.idmgs_mapping {
        Some(m) => match m.get(idmg) {
            Some(m) => m,
            None => {
                warn!("commande_prochain_attachment Idmg {} non mappe pour message uuid_message: {}", idmg, uuid_message);
                return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Idmg non mappe pour le fichier (1)"}), None)?))
            }
        },
        None => {
            warn!("commande_prochain_attachment Aucun mapping de idmg pour message uuid_message: {}", uuid_message);
            return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Idmg non mappe pour le fichier (2)"}), None)?))
        }
    };

    let fuuid_attachment = match &mapping.attachments_restants {
        Some(a) => {
            if a.len() > 0 {
                a.get(0).expect("attachment")
            } else {
                debug!("commande_prochain_attachment Aucun attachment disponible pour message uuid_message: {}", uuid_message);
                return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Aucun attachment disponible"}), None)?))
            }
        },
        None => {
            warn!("commande_prochain_attachment Aucuns attachment mappes pour message uuid_message: {}", uuid_message);
            return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Aucuns attachment mappes"}), None)?))
        }
    };

    // Marquer l'attachment comme en cours
    let ts_courant = Utc::now().timestamp();
    let ops = doc! {
        "$pull": {
            format!("idmgs_mapping.{}.attachments_restants", idmg): fuuid_attachment,
        },
        "$set": {
            format!("idmgs_mapping.{}.attachments_en_cours.{}", idmg, fuuid_attachment): {
                "last_update": ts_courant,
            },
        }
    };
    collection.update_one(filtre, ops, None).await?;

    // Repondre avec le fuuid
    let reponse = ReponseProchainAttachment { fuuid: Some(fuuid_attachment.into()), ok: true };
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

async fn commande_supprimer_message<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509 + VerificateurMessage
{
    debug!("commandes.commande_supprimer_message Consommer commande : {:?}", & m.message);
    let commande: TransactionSupprimerMessage = m.message.get_msg().map_contenu()?;
    debug!("commandes.commande_supprimer_message Commande parsed : {:?}", commande);

    let user_id = match m.get_user_id() {
        Some(u) => u,
        None => return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "userId manquant", "code": 403}), None)?))
    };

    // Autorisation: Action usager avec compte prive ou delegation globale
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    if role_prive {
        // Ok
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("commandes.commande_supprimer_message: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    }

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_supprimer_contacts<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commandes.commande_supprimer_contacts Consommer commande : {:?}", & m.message);
    let commande: TransactionSupprimerContacts = m.message.get_msg().map_contenu()?;
    debug!("commandes.commande_supprimer_contacts Commande parsed : {:?}", commande);

    todo!("fix me");
    // {
    //     let version_commande = m.message.get_entete().version;
    //     if version_commande != 1 {
    //         Err(format!("commandes.commande_supprimer_contacts: Version non supportee {:?}", version_commande))?
    //     }
    // }
    //
    // let user_id = match m.get_user_id() {
    //     Some(u) => u,
    //     None => return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "userId manquant", "code": 403}), None)?))
    // };
    //
    // // Autorisation: Action usager avec compte prive ou delegation globale
    // let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    // if role_prive {
    //     // Ok
    // } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
    //     // Ok
    // } else {
    //     Err(format!("commandes.commande_supprimer_contacts: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    // }
    //
    // // Traiter la transaction
    // Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_conserver_configuration_notifications<M>(middleware: &M, mut m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509 + VerificateurMessage
{
    debug!("commandes.commande_conserver_configuration_notifications Consommer commande : {:?}", & m.message);
    let mut commande: TransactionConserverConfigurationNotifications = m.message.get_msg().map_contenu()?;
    debug!("commandes.commande_conserver_configuration_notifications Commande parsed : {:?}", commande);

    // Autorisation: Action usager avec compte prive ou delegation globale
    if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("commandes.commande_supprimer_contacts: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    }

    if let Some(mut attachements) = m.message.parsed.attachements.take() {
        if let Some(smtp) = attachements.remove("smtp") {
            sauvegarde_attachement_cle(middleware, smtp).await?
        }
    }

    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

// async fn sauvegarde_attachement_cle<M>(middleware: &M, smtp: Value) -> Result<(), Box<dyn Error>>
//     where M: GenerateurMessages
// {
//     match serde_json::from_value::<CommandeSauvegarderCle>(smtp) {
//         Ok(cle) => {
//             debug!("commande_conserver_configuration_notifications Sauvegarder cle SMTP : {:?}", cle);
//             if let Some(p) = cle.partition.as_ref() {
//                 let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, COMMANDE_SAUVEGARDER_CLE)
//                     .exchanges(vec![Securite::L3Protege])
//                     .partition(p.to_owned())
//                     .build();
//                 match middleware.transmettre_commande(routage, &cle, true).await? {
//                     Some(TypeMessage::Valide(m)) => {
//                         let reponse: MessageReponse = m.message.parsed.map_contenu()?;
//                         if let Some(true) = reponse.ok {
//                             // Ok
//                         } else {
//                             Err(format!("commande_conserver_configuration_notifications Sauvegarder cle SMTP : Reponse ok != true"))?
//                         }
//                     },
//                     _ => Err(format!("commande_conserver_configuration_notifications Sauvegarder cle SMTP : Mauvais type reponse"))?
//                 }
//             } else {
//                 Err(format!("commandes.commande_conserver_configuration_notifications Erreur sauvegarde cle - partition n'est pas fournie"))?
//             }
//         },
//         Err(e) => Err(format!("commandes.commande_conserver_configuration_notifications Erreur mapping commande cle SMTP"))?
//     }
//
//     Ok(())
// }

async fn commande_upload_attachment<M>(middleware: &M, m: MessageValideAction)
                                       -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_upload_attachment Consommer : {:?}", & m.message);
    let evenement: CommandeUploadAttachment = m.message.get_msg().map_contenu()?;
    debug!("commande_upload_attachment parsed : {:?}", evenement);

    let idmg = evenement.idmg.as_str();
    let uuid_message = evenement.message_id.as_str();
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
            warn!("commande_upload_attachment Remettre le fuuid a la fin de la file, ajouter next_push_time");
            return Ok(None);
        },
        _ => {
            Err(format!("evenements.commande_upload_attachment Recu evenement inconnu (code: {}), on l'ignore", evenement.code))?
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

async fn commande_fuuid_verifier_existance<M>(middleware: &M, m: MessageValideAction)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_fuuid_verifier_existance Consommer : {:?}", & m.message);
    let commande: CommandeVerifierExistanceFuuidsMessage = m.message.get_msg().map_contenu()?;
    debug!("commande_fuuid_verifier_existance parsed : {:?}", commande);

    // Faire requete vers fichiers
    let routage = RoutageMessageAction::builder("fichiers", "fuuidVerifierExistance")
        .exchanges(vec![Securite::L2Prive])
        .build();
    let requete = json!({"fuuids": &commande.fuuids});
    let reponse = middleware.transmettre_requete(routage, &requete).await?;

    debug!("commande_fuuid_verifier_existance Reponse : {:?}", reponse);
    let mut set_ops = doc!{};
    if let TypeMessage::Valide(r) = reponse {
        let reponse_mappee: ReponseVerifierExistanceFuuidsMessage = r.message.parsed.map_contenu()?;
        for (key, value) in reponse_mappee.fuuids.into_iter() {
            if(value) {
                set_ops.insert(format!("attachments.{}", key), true);
            }
        }
    }

    if ! set_ops.is_empty() {
        let ops = doc! {
            "$set": set_ops,
            "$currentDate": {CHAMP_MODIFICATION: true},
        };
        let filtre = doc! { CHAMP_UUID_MESSAGE: &commande.message_id };
        let collection = middleware.get_collection(NOM_COLLECTION_INCOMING)?;
        collection.update_many(filtre, ops, None).await?;
    }

    Ok(None)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeConserverClesAttachment {
    pub cles: HashMap<String, CommandeSauvegarderCle>,
    pub preuves: HashMap<String, PreuvePossessionCles>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreuvePossessionCles {
    pub preuve: String,
    pub date: DateEpochSeconds,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponsePreuvePossessionCles {
    pub verification: HashMap<String, bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseCle {
    pub ok: Option<bool>
}

async fn commande_conserver_cles_attachments<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_conserver_cles_attachments Consommer commande : {:?}", & m.message);
    let commande: CommandeConserverClesAttachment = m.message.get_msg().map_contenu()?;
    debug!("commande_conserver_cles_attachments parsed : {:?}", commande);
    // debug!("Commande en json (DEBUG) : \n{:?}", serde_json::to_string(&commande));

    let fingerprint_client = match &m.message.certificat {
        Some(inner) => inner.fingerprint.clone(),
        None => Err(format!("commande_conserver_cles_attachments Envelopppe manquante"))?
    };

    let user_id = match m.get_user_id() {
        Some(inner) => inner,
        None => Err(format!("commande_conserver_cles_attachments Enveloppe sans user_id"))?
    };

    // Verifier aupres du maitredescles si les cles sont valides
    let reponse_preuves = {
        let requete_preuves = json!({"fingerprint": fingerprint_client, "preuves": &commande.preuves});
        let routage_maitrecles = RoutageMessageAction::builder(
            DOMAINE_NOM_MAITREDESCLES, REQUETE_MAITREDESCLES_VERIFIER_PREUVE)
            .exchanges(vec![Securite::L4Secure])
            .build();
        debug!("commande_conserver_cles_attachments Requete preuve possession cles : {:?}", requete_preuves);
        let reponse_preuve = match middleware.transmettre_requete(routage_maitrecles, &requete_preuves).await? {
            TypeMessage::Valide(m) => {
                match m.message.certificat.as_ref() {
                    Some(c) => {
                        if c.verifier_roles(vec![RolesCertificats::MaitreDesCles]) {
                            debug!("commande_conserver_cles_attachments Reponse preuve : {:?}", m);
                            let preuve_value: ReponsePreuvePossessionCles = m.message.get_msg().map_contenu()?;
                            Ok(preuve_value)
                        } else {
                            Err(format!("commandes.commande_conserver_cles_attachments Erreur chargement certificat de reponse verification preuve, certificat n'est pas de role maitre des cles"))
                        }
                    },
                    None => Err(format!("commandes.commande_conserver_cles_attachments Erreur chargement certificat de reponse verification preuve, certificat inconnu"))
                }
            },
            m => Err(format!("commandes.commande_conserver_cles_attachments Erreur reponse message verification cles, mauvais type : {:?}", m))
        }?;
        debug!("commande_conserver_cles_attachments Reponse verification preuve : {:?}", reponse_preuve);

        reponse_preuve.verification
    };

    let mut resultat_fichiers = HashMap::new();
    for mut hachage_bytes in commande.cles.keys() {
        let fuuid = hachage_bytes.as_str();

        let mut etat_cle = false;
        if Some(&true) == reponse_preuves.get(fuuid) {
            etat_cle = true;
        } else {
            // Tenter de sauvegarder la cle
            if let Some(cle) = commande.cles.get(fuuid) {
                debug!("commande_conserver_cles_attachments Sauvegarder cle fuuid {} : {:?}", fuuid, cle);
                let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, COMMANDE_SAUVEGARDER_CLE)
                    .exchanges(vec![Securite::L4Secure])
                    .timeout_blocking(5000)
                    .build();
                let reponse_cle = middleware.transmettre_commande(routage, &cle, true).await?;
                debug!("commande_conserver_cles_attachments Reponse sauvegarde cle : {:?}", reponse_cle);
                if let Some(reponse) = reponse_cle {
                    if let TypeMessage::Valide(mva) = reponse {
                        debug!("Reponse valide : {:?}", mva);
                        let reponse_mappee: ReponseCle = mva.message.get_msg().map_contenu()?;
                        etat_cle = true;
                    }
                }
            } else {
                debug!("commande_conserver_cles_attachments Aucune cle trouvee pour fuuid {} : {:?}", fuuid, commande.cles);
            }
        }

        if etat_cle {
            debug!("commande_conserver_cles_attachments Fuuid {} preuve OK", fuuid);
            resultat_fichiers.insert(fuuid.to_string(), true);
        } else {
            warn!("commande_copier_fichier_tiers Fuuid {} preuve refusee ou cle inconnue", fuuid);
            resultat_fichiers.insert(fuuid.to_string(), false);
        }
    }

    let reponse = json!({"resultat": resultat_fichiers});
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeGenererClewebpushNotifications {}

async fn generer_clewebpush_notifications<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509 + ChiffrageFactoryTrait + VerificateurMessage
{
    debug!("generer_clewebpush_notifications Consommer commande : {:?}", & m.message);
    let commande: CommandeGenererClewebpushNotifications = m.message.get_msg().map_contenu()?;
    debug!("generer_clewebpush_notifications parsed : {:?}", commande);

    let nid = Nid::X9_62_PRIME256V1; // NIST P-256 curve
    let group = EcGroup::from_curve_name(nid)?;
    let key = EcKey::generate(&group)?;
    let pem_prive = String::from_utf8(key.private_key_to_pem()?)?;
    let pem_public = String::from_utf8(key.public_key_to_pem()?)?;

    // Encoder public key URL-safe pour navigateur
    let vapid_builder = VapidSignatureBuilder::from_pem_no_sub(pem_prive.as_bytes())?;
    let public_bytes = vapid_builder.get_public_key();
    let public_key_str = general_purpose::URL_SAFE.encode(public_bytes);

    debug!("PEM PRIVE cle notification : \n{}\n{:?}", pem_prive, public_key_str);

    let data_dechiffre = json!({"cle_privee_pem": &pem_prive});
    let data_dechiffre_string = serde_json::to_string(&data_dechiffre)?;
    let data_dechiffre_bytes = data_dechiffre_string.as_bytes();

    // Creer transaction pour sauvegarder cles webpush
    let data_chiffre = {
        let mut chiffreur = middleware.get_chiffrage_factory().get_chiffreur()?;

        let mut output = [0u8; 2 * 1024];
        let output_size = chiffreur.update(data_dechiffre_bytes, &mut output)?;
        let (final_output_size, keys) = chiffreur.finalize(&mut output[output_size..])?;

        debug!("generer_clewebpush_notifications Data chiffre {} + {}\nOutput : {:?}",
            output_size, final_output_size, &output[..output_size+final_output_size]);
        let data_chiffre_multibase: String = multibase::encode(Base::Base64, &output[..output_size+final_output_size]);

        let mut identificateurs = HashMap::new();
        identificateurs.insert("type".to_string(), "notifications_webpush".to_string());
        debug!("commande_initialiser_profil Hachage bytes {}", keys.hachage_bytes);
        let cle_profil = keys.get_commande_sauvegarder_cles(DOMAINE_NOM, None, identificateurs)?;
        let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, COMMANDE_SAUVEGARDER_CLE)
            .exchanges(vec![Securite::L4Secure])
            .build();
        debug!("commande_initialiser_profil Sauvegarder cle {:?}", cle_profil);
        middleware.transmettre_commande(routage, &cle_profil, true).await?;

        // Sauvegarder cle chiffree
        let data_chiffre = DataChiffre {
            ref_hachage_bytes: Some(cle_profil.hachage_bytes.clone()),
            data_chiffre: data_chiffre_multibase,
            format: cle_profil.format.clone(),
            header: cle_profil.header.clone(),
            tag: cle_profil.tag.clone(),
        };

        debug!("generer_clewebpush_notifications Data chiffre : {:?}", data_chiffre);
        data_chiffre
    };

    // Generer nouvelle transaction
    let transaction = TransactionCleWebpush {
        data_chiffre,
        cle_publique_pem: pem_public,
        cle_publique_urlsafe: public_key_str.clone(),
    };

    debug!("generer_clewebpush_notifications Transaction cle webpush {:?}", transaction);

    let reponse = sauvegarder_traiter_transaction_serializable(
        middleware, &transaction, gestionnaire,
        DOMAINE_NOM, TRANSACTION_SAUVEGARDER_CLEWEBPUSH_NOTIFICATIONS).await?;

    // let transaction = middleware.formatter_message(
    //     &transaction, Some(DOMAINE_NOM), Some(m.action.as_str()), None, None, false)?;
    // let mut transaction = MessageValideAction::from_message_millegrille(
    //     transaction, TypeMessageOut::Transaction)?;
    //
    // // Conserver enveloppe pour validation
    // transaction.message.set_certificat(middleware.get_enveloppe_signature().enveloppe.clone());

    // // Traiter la transaction
    // Ok(sauvegarder_traiter_transaction(middleware, transaction, gestionnaire).await?)

    let reponse = json!({"ok": true, "webpush_public_key": public_key_str});
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeEmettreNotificationsUsager {
    user_id: String,
}

async fn emettre_notifications_usager<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509 + ChiffrageFactoryTrait
{
    debug!("emettre_notifications_usager Consommer commande : {:?}", & m.message);
    let commande: CommandeEmettreNotificationsUsager = m.message.get_msg().map_contenu()?;
    debug!("emettre_notifications_usager parsed : {:?}", commande);

    let user_id = commande.user_id.as_str();

    // Charger le document via update pour eviter multiple traitements des meme notifications.
    let filtre = doc! {
        CHAMP_USER_ID: user_id,
        CHAMP_EXPIRATION_LOCK_NOTIFICATIONS: {"$lte": Utc::now()}
    };
    let ops = doc! {
        "$set": {
            CHAMP_NOTIFICATIONS_PENDING: false,
            CHAMP_EXPIRATION_LOCK_NOTIFICATIONS: Utc::now() + Duration::seconds(60),
            CHAMP_UUID_TRANSACTIONS_NOTIFICATIONS: [],  // Vider notifications
        },
        "$currentDate": { CHAMP_MODIFICATION: true },
    };
    let options = FindOneAndUpdateOptions::builder()
        .return_document(ReturnDocument::Before)
        .build();
    let collection = middleware.get_collection(NOM_COLLECTION_NOTIFICATIONS_OUTGOING)?;
    let doc_notifications = collection.find_one_and_update(filtre, ops, Some(options)).await?;

    if let Some(d) = doc_notifications {
        let notifications: UsagerNotificationsOutgoing = convertir_bson_deserializable(d)?;
        if let Err(e) = generer_notification_usager(middleware, notifications).await {
            error!("commandes.emettre_notifications_usager Erreur generer notifications usager : {:?}", e);
        }
    } else {
        debug!("emettre_notifications_usager Notifications deja emises pour {}", user_id);
    }

    Ok(None)
}

async fn generer_notification_usager<M>(middleware: &M, notifications: UsagerNotificationsOutgoing)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + MongoDao
{
    // Charger profil usager. Si profil inconnu, on abandonne.
    let user_id = &notifications.user_id;

    let collection_profil = middleware.get_collection(NOM_COLLECTION_PROFILS)?;
    let profil_usager: ProfilReponse = match collection_profil.find_one(doc!{"user_id": &notifications.user_id}, None).await? {
        Some(u) => convertir_bson_deserializable(u)?,
        None => {
            return Err(format!("commandes.generer_notification_usager Usager {} n'a pas de profil", notifications.user_id))?
        }
    };

    // Charger configuration smtp, web push
    let collection_configuration = middleware.get_collection(NOM_COLLECTION_CONFIGURATION)?;
    let configuration_notifications: Option<ReponseConfigurationNotifications> = match collection_configuration.find_one(doc! {"config_key": "notifications"}, None).await? {
        Some(d) => Some(convertir_bson_deserializable(d)?),
        None => None
    };
    let configuration_cle_webpush: Option<TransactionCleWebpush> = match collection_configuration.find_one(doc! {"config_key": "cle_webpush"}, None).await? {
        Some(c) => Some(convertir_bson_deserializable(c)?),
        None => None
    };

    // Conserver hachage_bytes pour recuperer cles de dechiffrage
    let mut data_chiffre = Vec::new();
    let hachage_bytes_email = match profil_usager.email_chiffre {
        Some(e) => {
            let hachage = e.ref_hachage_bytes.clone();
            data_chiffre.push(e);
            hachage
        },
        None => None
    };
    let hachage_bytes_webpush = match configuration_cle_webpush.as_ref() {
        Some(inner) => {
            let hachage = inner.data_chiffre.ref_hachage_bytes.clone();
            data_chiffre.push(inner.data_chiffre.to_owned());
            hachage
        },
        None => None
    };

    // Demander cles de dechiffrage
    let data_dechiffre = dechiffrer_documents(middleware, data_chiffre).await?;

    let mut mapping_dechiffre = HashMap::new();
    for d in data_dechiffre {
        let data_string = String::from_utf8(d.data_dechiffre)?;
        debug!("Data dechiffre {:?} : {}", d.ref_hachage_bytes, data_string);
        if let Some(h) = d.ref_hachage_bytes {
            mapping_dechiffre.insert(h, serde_json::from_str::<Value>(data_string.as_str())?);
        }
    }

    let contenu_notification = generer_contenu_notification(
        middleware, configuration_notifications.as_ref(), &notifications).await?;

    let email_info = match hachage_bytes_email {
        Some(inner) => {
            if let Some(inner) = mapping_dechiffre.remove(inner.as_str()) {
                let value: ProfilUsagerDechiffre = serde_json::from_value(inner)?;
                if let Some(adresse_email) = value.email_adresse {
                    Some(EmailNotification {
                        address: adresse_email,
                        title: contenu_notification.title.clone(),
                        body: contenu_notification.body_email,
                    })
                } else {
                    None
                }
            } else {
                None
            }
        },
        None => None
    };

    let webpush_payload = match profil_usager.webpush_subscriptions {
        Some(subscriptions) => {
            match hachage_bytes_webpush {
                Some(inner) => {
                    match mapping_dechiffre.remove(inner.as_str()) {
                        Some(inner) => {
                            let value: WebpushConfigurationClePrivee = serde_json::from_value(inner)?;
                            let cle_serveur = value.cle_privee_pem;
                            match cle_serveur {
                                Some(cle) => {
                                    let mut messages = Vec::new();

                                    let body_json = json!({
                                        "title": &contenu_notification.title,
                                        "body": true,
                                        "payload": {
                                            "title": &contenu_notification.title,
                                            "body": &contenu_notification.body_webpush,
                                            // "url": "https://mg-dev1.maple.maceroc.com",
                                            "icon": contenu_notification.icon,
                                        }
                                    });
                                    let body_json = serde_json::to_string(&body_json)?;
                                    let vapid_sub = format!("mailto:{}", contenu_notification.email_from);

                                    for (_, s) in subscriptions {
                                        let subscription_info = SubscriptionInfo::new(s.endpoint, s.keys_p256dh, s.keys_auth);
                                        let mut sig_builder = VapidSignatureBuilder::from_pem(cle.as_bytes(), &subscription_info)?;
                                        sig_builder.add_claim("sub", vapid_sub.as_str());

                                        let mut builder = WebPushMessageBuilder::new(&subscription_info)?;
                                        builder.set_ttl(WEBPUSH_TTL);
                                        let content = body_json.as_bytes();
                                        builder.set_payload(ContentEncoding::Aes128Gcm, content);
                                        builder.set_vapid_signature(sig_builder.build()?);

                                        let message = builder.build()?;
                                        debug!("Message web push : {:?}", message);

                                        // let client = WebPushClient::new()?;
                                        // if let Err(e) = client.send(message).await {
                                        //     error!("Erreur web push : {:?}", e);
                                        // }

                                        let postmaster_message = PostmasterWebPushMessage::try_from(message)?;

                                        messages.push(postmaster_message);
                                    }

                                    Some(messages)
                                },
                                None => None
                            }
                        },
                        None => None
                    }
                },
                None => None
            }
        },
        None => None
    };

    let notification = NotificationOutgoingPostmaster {
        user_id: user_id.to_owned(),
        email: email_info,
        webpush: webpush_payload,
    };

    let routage = RoutageMessageAction::builder(DOMAINE_POSTMASTER, COMMANDE_POST_NOTIFICATION)
        .exchanges(vec![Securite::L1Public])
        .build();
    middleware.transmettre_commande(routage, &notification, false).await?;

    Ok(())
}

struct ContenuNotification {
    email_from: String,
    title: String,
    body_email: String,
    body_webpush: String,
    icon: Option<String>,
}

async fn generer_contenu_notification<M>(
    middleware: &M,
    configuration_notifications: Option<&ReponseConfigurationNotifications>,
    notifications: &UsagerNotificationsOutgoing
)
    -> Result<ContenuNotification, Box<dyn Error>>
    where M: GenerateurMessages
{
    let nombre_notifications = match notifications.message_id_notifications.as_ref() {
        Some(inner) => inner.len(),
        None => 0
    };
    let title = format!("{} nouveaux messages recus", nombre_notifications);
    let body_email = format!("{} nouveaux messages sont disponibles.\nAccedez au contenu sur la page web MilleGrilles.", nombre_notifications);
    let body_webpush = format!("{} nouveaux messages sont disponibles.\nAccedez au contenu sur la page web MilleGrilles.", nombre_notifications);

    let email_from = match &configuration_notifications {
        Some(inner) => match inner.email_from.as_ref() {
            Some(inner) => inner.to_owned(),
            None => String::from("no-reply@millegrilles.com")
        },
        None => String::from("no-reply@millegrilles.com")
    };

    let icon = match &configuration_notifications {
        Some(inner) => match inner.webpush.as_ref() {
            Some(inner) => inner.icon.to_owned(),
            None => None,
        },
        None => None,
    };

    Ok(ContenuNotification {
        email_from,
        title,
        body_email,
        body_webpush,
        icon,
    })
}

async fn commande_sauvegarder_usager_config_notifications<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509 + VerificateurMessage,
{
    debug!("commande_sauvegarder_usager_config_notifications Consommer : {:?}", & m.message);
    let commande: TransactionSauvegarderUsagerConfigNotifications = m.message.get_msg().map_contenu()?;
    debug!("commande_sauvegarder_usager_config_notifications parsed : {:?}", commande);

    // Verifier que le certificat a un user_id
    match &m.message.certificat {
        Some(c) => {
            if c.get_user_id()?.is_none() {
                Err(format!("commandes.commande_sauvegarder_usager_config_notifications User_id manquant"))?
            }
        },
        None => Err(format!("commandes.commande_sauvegarder_usager_config_notifications User_id manquant"))?
    }

    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_sauvegarder_subscription_webpush<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509 + VerificateurMessage,
{
    debug!("commande_sauvegarder_subscription_webpush Consommer : {:?}", & m.message);
    let commande: TransactionSauvegarderSubscriptionWebpush = m.message.get_msg().map_contenu()?;
    debug!("commande_sauvegarder_subscription_webpush parsed : {:?}", commande);

    // Verifier que le certificat a un user_id
    match &m.message.certificat {
        Some(c) => {
            if c.get_user_id()?.is_none() {
                Err(format!("commandes.commande_sauvegarder_subscription_webpush User_id manquant"))?
            }
        },
        None => Err(format!("commandes.commande_sauvegarder_subscription_webpush User_id manquant"))?
    }

    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_retirer_subscription_webpush<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509 + VerificateurMessage,
{
    debug!("commande_retirer_subscription_webpush Consommer : {:?}", & m.message);
    let commande: TransactionRetirerSubscriptionWebpush = m.message.get_msg().map_contenu()?;
    debug!("commande_retirer_subscription_webpush parsed : {:?}", commande);

    // Verifier que le certificat a un user_id
    match &m.message.certificat {
        Some(c) => {
            match c.get_user_id()? {
                Some(_) => (),  // Ok
                None => match c.verifier_roles(vec![RolesCertificats::Postmaster]) {
                    true => match commande.user_id.as_ref() {
                        Some(_) => (), // Ok
                        None => Err(format!("transactions.retirer_subscription_webpush Aucun user_id fourni par postmaster"))?
                    },
                    false => Err(format!("transactions.retirer_subscription_webpush Certificat sans user_id ou role != postmaster"))?
                }
            }
        },
        None => Err(format!("commandes.commande_retirer_subscription_webpush User_id manquant"))?
    }

    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

#[derive(Clone, Debug, Deserialize)]
struct InfoUsager {
    #[serde(rename="userId")]
    user_id: String,
    #[serde(rename="nomUsager")]
    nom_usager: String,
}

#[derive(Clone, Debug, Deserialize)]
struct ReponseListeUsagers {
    usagers: Vec<InfoUsager>
}

async fn commande_notifier<M>(middleware: &M, mut m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509 + VerificateurMessage
{
    debug!("commande_notifier Consommer : {:?}", & m.message);
    let commande: CommandeRecevoir = m.message.get_msg().map_contenu()?;
    debug!("commande_notifier parsed : {:?}", commande);

    let message_id = commande.message.id.clone();

    // Sauvegarder la cle au besoin
    if let Some(mut attachements) = m.message.parsed.attachements.take() {
        if let Some(cle_value) = attachements.remove("cle") {
            sauvegarde_attachement_cle(middleware, cle_value).await?;
        }
    }

    let enveloppe = match m.message.certificat.as_ref() {
        Some(e) => e.as_ref(),
        None => Err(format!("Erreur chargement certificat"))?
    };

    // Verifier que le certificat a un exchange ou user_id
    match &m.message.certificat {
        Some(c) => {
            match c.get_user_id()? {
                Some(_) => (),  // Ok
                None => match c.verifier_exchanges(vec![Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure]) {
                    true => (),  // Ok
                    false => Err(format!("transactions.retirer_subscription_webpush Certificat sans user_id ou sans exchange L1-L4"))?
                }
            }
        },
        None => Err(format!("commandes.commande_retirer_subscription_webpush Erreur chargement certificat pour notification"))?
    }

    // Determiner les destinataires
    let (destinataires, expiration) = match &commande.destinataires {
        Some(d) => (d.clone(), commande.expiration.clone()),
        None => {
            // Forcer expiration de la notification (volatile)
            let expiration = match commande.expiration {
                Some(e) => Some(e),
                None => Some(CONST_EXPIRATION_NOTIFICATION_DEFAUT)
            };
            // Charger la liste des proprietaires (requete a MaitreDesComptes)
            let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCOMPTES, ACTION_GET_LISTE_PROPRIETAIRES)
                .exchanges(vec![Securite::L3Protege])
                .build();
            let requete = json!({});
            match middleware.transmettre_requete(routage, &requete).await? {
                TypeMessage::Valide(m) => {
                    debug!("Reponse liste proprietaires : {:?}", m);
                    let reponse: ReponseListeUsagers = m.message.parsed.map_contenu()?;
                    let user_ids: Vec<String> = reponse.usagers.into_iter().map(|u| u.user_id).collect();
                    (user_ids, expiration)
                },
                _ => Err(format!("Erreur chargement liste proprietaires"))?
            }
        }
    };

    // Verifier si la notification est volatile (avec expiration).
    // Les notifications volatiles ne sont pas sauvegardees via transaction.
    match &commande.expiration {
        Some(e) => {
            // Sauvegarder la cle au besoin
            if let Some(mut attachements) = m.message.parsed.attachements.take() {
                if let Some(cle_value) = attachements.remove("cle") {
                    sauvegarde_attachement_cle(middleware, cle_value).await?;
                }
            }
            debug!("Sauvegarder notification volatile, expiration {}", e);
            recevoir_notification(middleware, message_id, &commande, enveloppe, destinataires).await?;
            Ok(middleware.reponse_ok()?)
        },
        None => {
            // Notification non volatile (avec destinataires, sans expiration)
            // sauvegarder sous forme de transaction
            debug!("Sauvegarder notification avec destinataires, sans expiration");
            Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
        }
    }
}

async fn recevoir_notification<M>(
    middleware: &M,
    message_id: String,
    notification: &CommandeRecevoir,
    // entete: &Entete,
    enveloppe: &EnveloppeCertificat,
    destinataires: Vec<String>
)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("recevoir_notification {:?} de {:?} pour {:?}", notification, enveloppe, destinataires);

    // let fp_certs = enveloppe.get_pem_vec();
    // let certificat_message_pem: Vec<String> = fp_certs.into_iter().map(|c| c.pem).collect();
    //
    // // Sauvegarder la cle au besoin
    // if let Some(cle) = notification.cle.as_ref() {
    //     if let Some(partition) = cle.entete.partition.as_ref() {
    //         debug!("Sauvegarder cle de notification avec partition {}", partition);
    //         let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, COMMANDE_SAUVEGARDER_CLE)
    //             .exchanges(vec![Securite::L3Protege])
    //             .partition(partition)
    //             .build();
    //         middleware.transmettre_commande(routage, cle, true).await?;
    //     }
    // }

    let message_bson = convertir_to_bson(notification.message.clone())?;

    let now: Bson = DateEpochSeconds::now().into();
    // let uuid_transaction = entete.uuid_transaction.as_str();

    let mut liste_usagers = Vec::new();
    for user_id in &destinataires {
        // Sauvegarder message pour l'usager
        debug!("transaction_recevoir Sauvegarder message pour usager : {}", user_id);
        // map_usagers.insert(user_id.to_owned(), Some(user_id.to_owned()));
        liste_usagers.push(DestinataireInfo {adresse: None, user_id: Some(user_id.to_owned())});

        let doc_user_reception = doc! {
            "user_id": user_id,
            // "message_id": &message_id,
            "lu": false,
            CHAMP_SUPPRIME: false,
            "date_reception": &now,
            "date_ouverture": None::<&str>,
            // "certificat_message": &certificat_message_pem,
            "message": &message_bson,

            // Attachments - note, pas encore supporte via notifications
            CHAMP_FICHIERS: None::<&str>,  // &attachments_bson,
            CHAMP_FICHIERS_COMPLETES: true,  // &attachments_recus,

            // Info specifique aux notifications
            "niveau": &notification.niveau,
            "expiration": notification.expiration,
        };

        debug!("recevoir_notification Inserer message {:?}", doc_user_reception);
        let collection = middleware.get_collection(NOM_COLLECTION_INCOMING)?;
        match collection.insert_one(&doc_user_reception, None).await {
            Ok(_r) => (),
            Err(e) => {
                let erreur_duplication = verifier_erreur_duplication_mongo(&*e.kind);
                if erreur_duplication {
                    info!("recevoir_notification Erreur duplication notification : {:?}", e);
                } else {
                    Err(e)?  // Relancer erreur
                }
            }
        }

        // Evenement de nouveau message pour front-end, notifications
        if let Ok(mut m) = convertir_bson_deserializable::<DocumentIncoming>(doc_user_reception) {
            // // let message_mappe: MessageIncoming =
            // let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_NOUVEAU_MESSAGE)
            //     .exchanges(vec![Securite::L2Prive])
            //     .partition(user_id)
            //     .build();
            // middleware.emettre_evenement(routage, &m).await?;

            let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_NOUVEAU_MESSAGE)
                .exchanges(vec![Securite::L2Prive])
                .partition(user_id)
                .build();

            match middleware.get_certificat(m.message.pubkey.as_str()).await {
                Some(inner) => {
                    let mut evenement = MessageIncomingClient::from(m);
                    evenement.certificat = Some(inner.get_pem_vec_extracted());
                    middleware.emettre_evenement(routage, &evenement).await?;
                },
                None => {
                    error!("transasctions.transaction_recevoir Erreur get_certificat {} du message {} pour emettre_evenement",
                        m.message.pubkey, m.message.id);
                }
            }

        }
    }

    if let Err(e) = emettre_notifications(
        middleware, &liste_usagers, message_id.as_str()).await {
        warn!("recevoir_notification Erreur emission notifications : {:?}", e);
    }

    Ok(())
}

async fn commande_recevoir_externe<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509 + VerificateurMessage + CleChiffrageHandler
{
    debug!("commandes.commande_recevoir_externe Consommer commande : {:?}", & m.message);
    let mut commande: CommandeRecevoirPostExterne = m.message.get_msg().map_contenu()?;
    debug!("commandes.commande_recevoir_externe Commande nouvelle versions parsed : {:?}", commande);

    let options = ValidationOptions::new(true, false, true);
    let mut enveloppe_message = MessageSerialise::from_parsed(commande.message)?;
    let mut enveloppe_transfert = MessageSerialise::from_parsed(commande.transfert)?;
    let enveloppe_cles = commande.cles;

    // Valider messages
    {
        let validation_message = enveloppe_message.valider(middleware, Some(&options)).await?;
        if validation_message.valide() == false {
            warn!("commande_recevoir_externe Message inter-millegrille invalide : {:?}", validation_message);
            if validation_message.certificat_valide == false {
                return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "Certificat message invalide"}), None)?))
            }
            return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "Hachage/Signature message invalide"}), None)?))
        }

        let validation_transfert = enveloppe_transfert.valider(middleware, Some(&options)).await?;
        if validation_transfert.valide() == false {
            warn!("commande_recevoir_externe Message transfert invalide : {:?}", validation_transfert);
            return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "Message transfert invalide"}), None)?))
        }
    }

    // Preparer commande/transaction sauvegarder cle - permet de valider le message
    let commande_sauvegarder_cle = match enveloppe_message.parsed.dechiffrage {
        Some(inner) => {
            let hachage_bytes = match inner.hachage {
                Some(inner) => inner,
                None => {
                    warn!("commande_recevoir_externe Message dechiffrage.hachage_bytes manquant");
                    return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "Message dechiffrage.hachage_bytes manquant"}), None)?))
                }
            };

            let mut identificateurs_document = HashMap::new();
            identificateurs_document.insert("message".to_string(), "true".to_string());

            CommandeSauvegarderCle {
                hachage_bytes,
                domaine: DOMAINE_NOM.into(),
                identificateurs_document,
                signature_identite: "".to_string(),
                cles: enveloppe_cles,
                format: FormatChiffrage::try_from(inner.format.as_str())?,
                iv: None,
                tag: None,
                header: inner.header,
                partition: None,
                fingerprint_partitions: None,
            }
        },
        None => {
            warn!("commande_recevoir_externe Message sans information de dechiffrage");
            return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "Message sans information de dechiffrage"}), None)?))
        }
    };
    debug!("Commande sauvegarder cles : {:?}", commande_sauvegarder_cle);

    // Dechiffrer destinataires
    let commande_transfert = match dechiffrer_cle_message(middleware, &enveloppe_transfert.parsed).await {
        Ok(cle_secrete) => {
            let transfert_inter = MessageInterMillegrille::try_from(enveloppe_transfert.parsed)?;
            let contenu_dechiffre = transfert_inter.dechiffrer_avec_cle(middleware, cle_secrete)?;
            let commande_transfert: CommandeTransfertPoster = serde_json::from_slice(&contenu_dechiffre.data_dechiffre[..])?;
            commande_transfert
        },
        Err(e) => {
            warn!("commande_recevoir_externe Message transfert erreur dechiffrage cles : {:?}", e);
            return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "Message transfert sans cles"}), None)?))
        }
    };

    debug!("commande_recevoir_externe Commande transfert dechiffree : {:?}", commande_transfert);

    // Faire correspondre les destinataires aux usagers locaux

    // Sauvegarder cle du message


    // Traiter transaction du message


    todo!("fix me");
}

async fn dechiffrer_cle_message<M>(middleware: &M, message: &MessageMilleGrille)
    -> Result<CleSecrete, Box<dyn Error>>
    where M: GenerateurMessages
{
    let enveloppe_privee = middleware.get_enveloppe_signature();
    let fingerprint_ca = enveloppe_privee.enveloppe_ca.fingerprint.as_str();

    let cles_transfert = match message.dechiffrage.as_ref() {
        Some(inner) => match inner.cles.as_ref() {
            Some(inner) => inner,
            None => Err(format!("commande_recevoir_externe Message transfert sans cles de dechiffrage (1)"))?
        },
        None => Err(format!("commande_recevoir_externe Message transfert sans cles de dechiffrage (2)"))?
    };

    for (k, v) in cles_transfert {
        if k.as_str() == fingerprint_ca {
            continue;   // Skip, c'est la cle chiffree pour le CA
        }

        debug!("Tenter de dechiffrer cles de transfert : {}", k);
        let commande = CommandeDechiffrerCle { cle: v.clone(), fingerprint: v.clone() };
        let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, COMMANDE_DECHIFFRER_CLE)
            .exchanges(vec![Securite::L4Secure])
            .partition(k)
            .build();

        match middleware.transmettre_commande(routage, &commande, true).await {
            Ok(inner) => {
                if let Some(TypeMessage::Valide(reponse)) = inner {
                    debug!("Reponse cle dechiffree {:?}", reponse.message);
                    match reponse.message.parsed.map_contenu::<CommandeCleRechiffree>() {
                        Ok(inner) => {
                            if let Some(cle_str) = inner.cle {
                                let (_, cle_bytes) = multibase::decode(cle_str.as_str())?;
                                let cle_secrete_recue = dechiffrer_asymmetrique_ed25519(
                                    &cle_bytes[..], enveloppe_privee.cle_privee())?;

                                // Cle recue et dechiffree avec succes
                                return Ok(cle_secrete_recue);

                            } else {
                                info!("Erreur reception reponse dechiffre cle, aucune cle recue");
                                continue;
                            }
                        },
                        Err(e) => {
                            info!("Erreur reception reponse dechiffre cle : {:?}", e);
                            continue;
                        }
                    };
                }
            },
            Err(e) => {
                info!("Erreur reception reponse dechiffre cle : {:?}", e);
            }
        }
    }

    Err(format!("Cle non dechiffrable"))?
}

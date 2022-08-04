use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::sync::Arc;

use log::{debug, error, info, warn};
use millegrilles_common_rust::{serde_json, serde_json::json};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::certificats::{EnveloppeCertificat, ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::constantes::Securite::L2Prive;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille, MessageSerialise};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::middleware::sauvegarder_traiter_transaction;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, MongoDao};
use millegrilles_common_rust::mongodb::Collection;
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, FindOptions, Hint, ReturnDocument, UpdateOptions};
use millegrilles_common_rust::recepteur_messages::{MessageValideAction, TypeMessage};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::Transaction;
use millegrilles_common_rust::verificateur::{ValidationOptions, VerificateurMessage};

use crate::gestionnaire::GestionnaireMessagerie;
use crate::constantes::*;
use crate::transactions::*;
use crate::message_structs::*;
use crate::pompe_messages::{marquer_outgoing_resultat, verifier_fin_transferts_attachments};

pub async fn consommer_commande<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage + ValidateurX509
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

        // Transactions
        TRANSACTION_POSTER => commande_poster(middleware, m, gestionnaire).await,
        TRANSACTION_RECEVOIR => commande_recevoir(middleware, m, gestionnaire).await,
        TRANSACTION_INITIALISER_PROFIL => commande_initialiser_profil(middleware, m, gestionnaire).await,
        TRANSACTION_MAJ_CONTACT => commande_maj_contact(middleware, m, gestionnaire).await,
        TRANSACTION_LU => commande_lu(middleware, m, gestionnaire).await,
        TRANSACTION_SUPPRIMER_MESSAGES => commande_supprimer_message(middleware, m, gestionnaire).await,
        TRANSACTION_SUPPRIMER_CONTACTS => commande_supprimer_contacts(middleware, m, gestionnaire).await,

        // Commandes inconnues
        _ => Err(format!("core_backup.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, m.action))?,
    }
}

async fn commande_poster<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_poster Consommer commande : {:?}", & m.message);
    let commande: CommandePoster = m.message.get_msg().map_contenu(None)?;
    debug!("Commande nouvelle versions parsed : {:?}", commande);

    {
        let version_commande = m.message.get_entete().version;
        if version_commande != 1 {
            Err(format!("commandes.commande_poster: Version non supportee {:?}", version_commande))?
        }
    }

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

    // TODO Valider message

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_recevoir<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509 + VerificateurMessage
{
    debug!("commandes.commande_recevoir Consommer commande : {:?}", & m.message);
    let commande: CommandeRecevoirPost = m.message.get_msg().map_contenu(None)?;
    debug!("commandes.commande_recevoir Commande nouvelle versions parsed : {:?}", commande);

    {
        let version_commande = m.message.get_entete().version;
        if version_commande != 1 {
            Err(format!("commandes.commande_recevoir: Version non supportee {:?}", version_commande))?
        }
    }

    let user_id = m.get_user_id();
    match m.verifier_exchanges(vec!(Securite::L2Prive, Securite::L3Protege, Securite::L4Secure)) {
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
                Err(format!("commandes.commande_recevoir: Commande autorisation invalide pour message {:?}", m.correlation_id))?
            }
        }
    }

    let message_ref = &commande.message;

    let cert_millegrille_pem = match message_ref.get("_millegrille") {
        Some(c) => {
            debug!("commande_recevoir Utiliser certificat de millegrille pour valider : {:?}", c);
            let millegrille_pem: String = serde_json::from_value(c.to_owned())?;
            Some(millegrille_pem)
        },
        None => {
            debug!("commande_recevoir Aucun certificat de millegrille pour valider");
            None
        }
    };

    let enveloppe_cert: Arc<EnveloppeCertificat> = match message_ref.get("_certificat") {
        Some(c) => {
            let certificat_pem: Vec<String> = serde_json::from_value(c.to_owned())?;
            match cert_millegrille_pem.as_ref() {
                Some(c) => middleware.charger_enveloppe(&certificat_pem, None, Some(c.as_str())).await?,
                None => {
                    // Millegrille locale, charger le certificat fourni
                    middleware.charger_enveloppe(&certificat_pem, None, None).await?
                }
            }
        },
        None => {
            error!("commande_recevoir Erreur _certificat manquant");
            let reponse_erreur = json!({"ok": false, "err": "Erreur, _certificat manquant"});
            return Ok(Some(middleware.formatter_reponse(&reponse_erreur, None)?));
        }
    };

    let mut message = MessageSerialise::from_serializable(&commande.message)?;
    debug!("Valider message avec certificat {:?}", enveloppe_cert);
    message.set_certificat(enveloppe_cert);

    match cert_millegrille_pem.as_ref() {
        Some(c) => {
            let cert = middleware.charger_enveloppe(&vec![c.to_owned()], None, None).await?;
            message.set_millegrille(cert);
        },
        None => ()
    }

    let options_validation = ValidationOptions::new(true, true, true);
    match middleware.verifier_message(&mut message, Some(&options_validation)) {
        Ok(resultat) => {
            if ! resultat.valide() {
                error!("commande_recevoir Erreur validation message : {:?}", resultat);
                let reponse_erreur = json!({"ok": false, "err": "Erreur validation message", "detail": format!("{:?}", resultat)});
                return Ok(Some(middleware.formatter_reponse(&reponse_erreur, None)?));
            }
        },
        Err(e) => {
            error!("commande_recevoir Erreur validation message : {:?}", e);
            let reponse_erreur = json!({"ok": false, "err": "Erreur validation message", "detail": format!("{:?}", e)});
            return Ok(Some(middleware.formatter_reponse(&reponse_erreur, None)?));
        }
    }

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_initialiser_profil<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commandes.commande_initialiser_profil Consommer commande : {:?}", & m.message);
    let commande: TransactionInitialiserProfil = m.message.get_msg().map_contenu(None)?;
    debug!("commandes.commande_initialiser_profil Commande nouvelle versions parsed : {:?}", commande);

    {
        let version_commande = m.message.get_entete().version;
        if version_commande != 1 {
            Err(format!("commandes.commande_initialiser_profil: Version non supportee {:?}", version_commande))?
        }
    }

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
    let filtre = doc! {CHAMP_USER_ID: user_id};
    let doc_profil = collection.find_one(filtre, None).await?;
    if doc_profil.is_some() {
        return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "profil existe deja", "code": 400}), None)?))
    }

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_maj_contact<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commandes.commande_maj_contact Consommer commande : {:?}", & m.message);
    let commande: Contact = m.message.get_msg().map_contenu(None)?;
    debug!("commandes.commande_maj_contact Commande nouvelle versions parsed : {:?}", commande);

    if commande.nom.len() == 0 {
        // Rejeter
        return Ok(Some(middleware.formatter_reponse(&json!({"ok": false, "err": "Nom vide"}), None)?));
    }

    {
        let version_commande = m.message.get_entete().version;
        if version_commande != 1 {
            Err(format!("commandes.commande_initialiser_profil: Version non supportee {:?}", version_commande))?
        }
    }

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
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commandes.commande_lu Consommer commande : {:?}", & m.message);
    let commande: CommandeLu = m.message.get_msg().map_contenu(None)?;
    debug!("commandes.commande_lu Commande nouvelle versions parsed : {:?}", commande);

    {
        let version_commande = m.message.get_entete().version;
        if version_commande != 1 {
            Err(format!("commandes.commande_initialiser_profil: Version non supportee {:?}", version_commande))?
        }
    }

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
    let commande: CommandeConfirmerTransmission = m.message.get_msg().map_contenu(None)?;
    debug!("commande_confirmer_transmission Commande parsed : {:?}", commande);

    let uuid_message = commande.uuid_message.as_str();
    let idmg = commande.idmg.as_str();

    let destinataires = match commande.destinataires.as_ref() {
        Some(d) => {
            d.iter().map(|d| d.destinataire.clone()).collect()
        },
        None => Vec::new()
    };

    let result_code = commande.code as u32;
    let processed = match &commande.code {
        200 => true,
        201 => true,
        202 => true,
        _ => false
    };

    marquer_outgoing_resultat(middleware, uuid_message, idmg, &destinataires, processed, result_code).await?;

    Ok(None)
}

async fn commande_prochain_attachment<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMessagerie)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + MongoDao + GenerateurMessages
{
    debug!("commande_confirmer_transmission Consommer commande : {:?}", & m.message);
    let commande: CommandeProchainAttachment = m.message.get_msg().map_contenu(None)?;
    debug!("commande_confirmer_transmission Commande parsed : {:?}", commande);

    let uuid_message = commande.uuid_message.as_str();
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
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commandes.commande_supprimer_message Consommer commande : {:?}", & m.message);
    let commande: TransactionSupprimerMessage = m.message.get_msg().map_contenu(None)?;
    debug!("commandes.commande_supprimer_message Commande parsed : {:?}", commande);

    {
        let version_commande = m.message.get_entete().version;
        if version_commande != 1 {
            Err(format!("commandes.commande_supprimer_message: Version non supportee {:?}", version_commande))?
        }
    }

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
    let commande: TransactionSupprimerContacts = m.message.get_msg().map_contenu(None)?;
    debug!("commandes.commande_supprimer_contacts Commande parsed : {:?}", commande);

    {
        let version_commande = m.message.get_entete().version;
        if version_commande != 1 {
            Err(format!("commandes.commande_supprimer_contacts: Version non supportee {:?}", version_commande))?
        }
    }

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
        Err(format!("commandes.commande_supprimer_contacts: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    }

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_upload_attachment<M>(middleware: &M, m: MessageValideAction)
                                       -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
{
    debug!("commande_upload_attachment Consommer : {:?}", & m.message);
    let evenement: CommandeUploadAttachment = m.message.get_msg().map_contenu(None)?;
    debug!("commande_upload_attachment parsed : {:?}", evenement);

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
    let commande: CommandeVerifierExistanceFuuidsMessage = m.message.get_msg().map_contenu(None)?;
    debug!("commande_fuuid_verifier_existance parsed : {:?}", commande);

    // Faire requete vers fichiers
    let routage = RoutageMessageAction::builder("fichiers", "fuuidVerifierExistance")
        .exchanges(vec![L2Prive])
        .build();
    let requete = json!({"fuuids": &commande.fuuids});
    let reponse = middleware.transmettre_requete(routage, &requete).await?;

    debug!("commande_fuuid_verifier_existance Reponse : {:?}", reponse);
    let mut set_ops = doc!{};
    if let TypeMessage::Valide(r) = reponse {
        let reponse_mappee: ReponseVerifierExistanceFuuidsMessage = r.message.parsed.map_contenu(None)?;
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
        let filtre = doc! { "uuid_message": &commande.uuid_message };
        let collection = middleware.get_collection(NOM_COLLECTION_INCOMING)?;
        collection.update_many(filtre, ops, None).await?;
    }

    Ok(None)
}
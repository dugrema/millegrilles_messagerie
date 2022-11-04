use std::collections::HashMap;
use millegrilles_common_rust::formatteur_messages::DateEpochSeconds;
use millegrilles_common_rust::serde::{Deserialize, Serialize};

pub const DOMAINE_NOM: &str = "Messagerie";
pub const DOMAINE_POSTMASTER: &str = "postmaster";
pub const NOM_COLLECTION_TRANSACTIONS: &str = "Messagerie";
pub const NOM_COLLECTION_INCOMING: &str = "Messagerie/incoming";
pub const NOM_COLLECTION_OUTGOING: &str = "Messagerie/outgoing";
pub const NOM_COLLECTION_OUTGOING_PROCESSING: &str = "Messagerie/outgoing_processing";
pub const NOM_COLLECTION_ATTACHMENTS: &str = "Messagerie/attachments";
pub const NOM_COLLECTION_ATTACHMENTS_PROCESSING: &str = "Messagerie/attachments_processing";
pub const NOM_COLLECTION_PROFILS: &str = "Messagerie/profils";
pub const NOM_COLLECTION_CONTACTS: &str = "Messagerie/contacts";

pub const DOMAINE_FICHIERS_NOM: &str = "fichiers";

pub const NOM_Q_TRANSACTIONS: &str = "Messagerie/transactions";
pub const NOM_Q_VOLATILS: &str = "Messagerie/volatils";
pub const NOM_Q_TRIGGERS: &str = "Messagerie/triggers";
pub const NOM_Q_MESSAGE_POMPE: &str = "Messagerie/messagePompe";

pub const REQUETE_GET_MESSAGES: &str = "getMessages";
pub const REQUETE_GET_PERMISSION_MESSAGES: &str = "getPermissionMessages";
pub const REQUETE_GET_PROFIL: &str = "getProfil";
pub const REQUETE_GET_CONTACTS: &str = "getContacts";
pub const REQUETE_GET_REFERENCE_CONTACTS: &str = "getReferenceContacts";
pub const REQUETE_ATTACHMENT_REQUIS: &str = "attachmentRequis";
pub const REQUETE_GET_REFERENCE_MESSAGES: &str = "getReferenceMessages";
pub const REQUETE_GET_MESSAGES_ATTACHMENTS: &str = "getMessagesAttachments";

pub const COMMANDE_CONFIRMER_TRANSMISSION: &str = "confirmerTransmission";
pub const COMMANDE_PROCHAIN_ATTACHMENT: &str = "prochainAttachment";
pub const COMMANDE_ACTIVITE_FUUIDS: &str = "confirmerActiviteFuuids";

pub const TRANSACTION_POSTER: &str = "poster";
pub const TRANSACTION_RECEVOIR: &str = "recevoir";
pub const TRANSACTION_INITIALISER_PROFIL: &str = "initialiserProfil";
pub const TRANSACTION_MAJ_CONTACT: &str = "majContact";
pub const TRANSACTION_LU: &str = "lu";
pub const TRANSACTION_TRANSFERT_COMPLETE: &str = "transfertComplete";
pub const TRANSACTION_SUPPRIMER_MESSAGES: &str = "supprimerMessages";
pub const TRANSACTION_SUPPRIMER_CONTACTS: &str = "supprimerContacts";
pub const TRANSACTION_CONFIRMER_TRANMISSION_MILLEGRILLE: &str = "confirmerTransmissionMillegrille";

// pub const COMMANDE_INDEXER: &str = "indexerContenu";

pub const COMMANDE_UPLOAD_ATTACHMENT: &str = "uploadAttachment";
pub const COMMANDE_FUUID_VERIFIER_EXISTANCE: &str = "fuuidVerifierExistance";
pub const EVENEMENT_POMPE_POSTE: &str = "pompePoste";
pub const EVENEMENT_MAJ_CONTACT: &str = "majContact";
pub const EVENEMENT_NOUVEAU_MESSAGE: &str = "nouveauMessage";
pub const EVENEMENT_MESSAGE_LU: &str = "messageLu";
pub const EVENEMENT_MESSAGES_SUPPRIMES: &str = "messagesSupprimes";
pub const EVENEMENT_CONTACTS_SUPPRIMES: &str = "contactsSupprimes";
pub const EVENEMENT_FICHIERS_CONSIGNE: &str = "consigne";
pub const EVENEMENT_CONFIRMER_ETAT_FUUIDS: &str = "confirmerEtatFuuids";
pub const EVENEMENT_CONFIRMER_MESSAGE_COMPLETE: &str = "confirmerMessageComplete";

pub const CHAMP_FUUID: &str = "fuuid";  // UUID fichier
pub const CHAMP_FUUIDS: &str = "fuuids";
pub const CHAMP_TUUID: &str = "tuuid";  // UUID transaction initiale (fichier ou collection)
pub const CHAMP_TUUIDS: &str = "tuuids";
pub const CHAMP_CUUID: &str = "cuuid";  // UUID collection de tuuids
pub const CHAMP_CUUIDS: &str = "cuuids";  // Liste de cuuids (e.g. appartenance a plusieurs collections)
pub const CHAMP_SUPPRIME: &str = "supprime";
pub const CHAMP_NOM: &str = "nom";
pub const CHAMP_NOM_USAGER: &str = "nomUsager";
pub const CHAMP_TITRE: &str = "titre";
pub const CHAMP_MIMETYPE: &str = "mimetype";
pub const CHAMP_FUUID_V_COURANTE: &str = "fuuid_v_courante";
pub const CHAMP_FAVORIS: &str = "favoris";
pub const CHAMP_FUUID_MIMETYPES: &str = "fuuidMimetypes";
pub const CHAMP_FLAG_INDEXE: &str = "flag_indexe";
pub const CHAMP_FLAG_MEDIA: &str = "flag_media";
pub const CHAMP_FLAG_MEDIA_TRAITE: &str = "flag_media_traite";
pub const CHAMP_USER_ID: &str = "user_id";
pub const CHAMP_DATE_RECEPTION: &str = "date_reception";
pub const CHAMP_DATE_ENVOI: &str = "date_envoi";
pub const CHAMP_FLAG_LU: &str = "lu";
pub const CHAMP_UUID_MESSAGE: &str = "uuid_message";
pub const CHAMP_LAST_PROCESSED: &str = "last_processed";
pub const CHAMP_UUID_CONTACT: &str = "uuid_contact";
pub const CHAMP_UUID_CONTACTS: &str = "uuid_contacts";
pub const CHAMP_ATTACHMENTS_TRAITES: &str = "attachments_traites";
pub const CHAMP_ATTACHMENTS: &str = "attachments";
pub const CHAMP_ATTACHMENTS_RETRY: &str = "attachments_retry";

pub const CODE_UPLOAD_DEBUT: u32 = 1;
pub const CODE_UPLOAD_ENCOURS: u32 = 2;
pub const CODE_UPLOAD_TERMINE: u32 = 3;
pub const CODE_UPLOAD_ERREUR: u32 = 4;

pub const CONST_ADRESSE_SEPARATEUR_HOST: &str = ":";
pub const CONST_ADRESSE_PREFIXE_USAGER: &str = "@";

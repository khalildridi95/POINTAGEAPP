CREATE TABLE IF NOT EXISTS employes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nom TEXT NOT NULL,
  email TEXT,
  password TEXT,
  role TEXT DEFAULT 'user',
  matricule TEXT
);
CREATE TABLE IF NOT EXISTS camp_aff (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  camping TEXT,
  affaire TEXT
);
CREATE TABLE IF NOT EXISTS planning (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  date TEXT,
  salarie TEXT,
  matricule TEXT,
  camping TEXT,
  affaire TEXT,
  tache TEXT,
  debut TEXT,
  fin TEXT,
  commentaire TEXT
);
CREATE TABLE IF NOT EXISTS pointages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  date TEXT,
  type_personne TEXT,
  nom TEXT,
  nature TEXT,
  camping TEXT,
  affaire TEXT,
  commentaire TEXT,
  debut TEXT,
  pause TEXT,
  reprise TEXT,
  fin TEXT,
  travail_hhmm TEXT,
  depl_hhmm TEXT,
  matricule TEXT
);
CREATE TABLE IF NOT EXISTS payes_validation (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  date TEXT,
  salarie TEXT,
  travail_hhmm TEXT,
  depl_hhmm TEXT,
  panier_midi TEXT,
  panier_soir TEXT,
  zone TEXT,
  forfait_trajet TEXT,
  hs_hhmm TEXT,
  hnuit_hhmm TEXT,
  decouches TEXT,
  forfait_we TEXT,
  statut TEXT,
  valide_par TEXT,
  valide_le TEXT,
  commentaire TEXT
);
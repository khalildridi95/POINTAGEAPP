// Ajoute en haut du fichier :
import xlsx from "xlsx";
import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import Database from "better-sqlite3";
import path from "path";
import { fileURLToPath } from "url";
import jwt from "jsonwebtoken"; // JWT sans cookie

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- CONFIG ---
const PORT = process.env.PORT || 3000;
const DB_FILE = process.env.DB_FILE || "./data.sqlite";
const JWT_SECRET = process.env.JWT_SECRET || "change-me-please";
const JWT_EXPIRES_IN = "12h";

// --- CORS ---
const allowedOrigins = [
  "http://localhost:3000",
  "http://localhost:5173",
  "https://khalildridi95.github.io",       // Front GitHub Pages
  "https://pointage-oeax.onrender.com"     // Backend Render
];

// --- DB ---
const db = new Database(DB_FILE);
db.pragma("journal_mode = WAL");

// Tables
db.exec(`
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
`);

// Seed minimal
const rowCount = db.prepare("SELECT COUNT(*) AS n FROM employes").get().n;
if (rowCount === 0) {
  db.prepare(`
    INSERT INTO employes (nom,email,password,role,matricule)
    VALUES ('demo','demo@example.com','demo','admin','M001')
  `).run();
  console.log("Seed employes: demo/demo (admin)");
}

// Helpers temps
function hhmmToMinutes(s) {
  if (!s) return 0;
  const m = String(s).trim().match(/^(\d{1,2}):(\d{2})$/);
  if (!m) return 0;
  return parseInt(m[1], 10) * 60 + parseInt(m[2], 10);
}
function minutesToHHMM(m) {
  const h = Math.floor(m / 60);
  const mm = m % 60;
  return `${h}:${String(mm).padStart(2, "0")}`;
}
function computeDurationMinutes(debut, fin, pause, reprise) {
  const d = hhmmToMinutes(debut);
  const f = hhmmToMinutes(fin);
  if (!d && !f) return 0;
  let dur = Math.max(0, f - d);
  const p = hhmmToMinutes(pause);
  const r = hhmmToMinutes(reprise);
  if (p || r) dur -= Math.max(0, (r || 0) - (p || 0));
  return Math.max(0, dur);
}

// --- Express app ---
const app = express();
app.use(cors({
  origin: allowedOrigins,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: false, // pas de cookie
}));
app.use(bodyParser.json());

// Statique
app.use(express.static(path.join(__dirname, "public")));

// Santé
app.get("/api/ping", (_req, res) => res.json({ pong: true }));

// ----------- AUTH JWT (Bearer) -----------
const publicPaths = new Set(["/ping", "/login", "/getIdentifiants"]);

function requireAuth(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: "unauthorized" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    return next();
  } catch {
    return res.status(401).json({ error: "unauthorized" });
  }
}

// Garde globale /api
app.use("/api", (req, res, next) => {
  if (req.method === "OPTIONS") return next();
  if (publicPaths.has(req.path)) return next();
  return requireAuth(req, res, next);
});

// Login
app.post("/api/login", (req, res) => {
  const { login, password } = req.body || {};
  if (!login || !password) return res.status(400).json({ error: "missing credentials" });
  const row = db.prepare("SELECT nom, password, role, matricule FROM employes WHERE lower(nom)=lower(?)").get(login);
  if (!row) return res.status(401).json({ error: "invalid credentials" });

  // Si tu hashes : if (!bcrypt.compareSync(password, row.password)) return res.status(401).json({error:"invalid credentials"});
  if (row.password !== password) return res.status(401).json({ error: "invalid credentials" });

  const payload = { login: row.nom, role: (row.role || "user").toLowerCase(), matricule: row.matricule || "" };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
  res.json({ ok: true, role: payload.role, token });
});

// ----------- AUTH / LISTES -----------
app.get("/api/getIdentifiants", (req, res) => {
  const list = db.prepare("SELECT DISTINCT nom FROM employes ORDER BY nom COLLATE NOCASE").all().map(r => r.nom);
  res.json(list);
});

// Compat (non utilisé si tu passes par /api/login)
app.post("/api/checkLogin", (req, res) => {
  const { login, password } = req.body || {};
  if (!login || !password) return res.json(false);
  const row = db.prepare("SELECT password FROM employes WHERE lower(nom)=lower(?)").get(login);
  res.json(row && row.password === password);
});
app.post("/api/getRoleForLogin", (req, res) => {
  const { login } = req.body || {};
  const row = db.prepare("SELECT role FROM employes WHERE lower(nom)=lower(?)").get(login || "");
  const role = (row && row.role || "user").toLowerCase();
  res.json(role === "admin" || role === "administrateur" ? "admin" : role === "compta" ? "compta" : "user");
});

// Employés
app.get("/api/getEmployes", (req, res) => {
  const rows = db.prepare("SELECT nom,email,password,role,matricule FROM employes ORDER BY nom COLLATE NOCASE").all();
  res.json(rows);
});
app.post("/api/saveEmployes", (req, res) => {
  const list = Array.isArray(req.body) ? req.body : [];
  const tx = db.transaction(() => {
    db.prepare("DELETE FROM employes").run();
    const ins = db.prepare("INSERT INTO employes (nom,email,password,role,matricule) VALUES (?,?,?,?,?)");
    list.forEach(e => {
      // Si hashage : const hashed = bcrypt.hashSync(e.password || "", 10);
      ins.run(e.nom || "", e.email || "", e.password || "", e.role || "user", e.matricule || "");
    });
  });
  tx();
  res.json({ ok: true, count: list.length });
});

// Campings / Affaires
app.get("/api/getCampingsEtAffaires", (req, res) => {
  const rows = db.prepare("SELECT camping, affaire FROM camp_aff ORDER BY camping COLLATE NOCASE, affaire COLLATE NOCASE").all();
  res.json(rows);
});
app.post("/api/saveCampingsEtAffaires", (req, res) => {
  const list = Array.isArray(req.body) ? req.body : [];
  const tx = db.transaction(() => {
    db.prepare("DELETE FROM camp_aff").run();
    const ins = db.prepare("INSERT INTO camp_aff (camping, affaire) VALUES (?,?)");
    list.forEach(e => ins.run(e.camping || "", e.affaire || ""));
  });
  tx();
  res.json({ ok: true, count: list.length });
});
app.get("/api/getLogoUrlDirect", (_req, res) => {
  res.json("https://www.pcelec.fr/wp-content/uploads/2020/01/pc-elec-sans-ombre.png");
});
app.post("/api/getMatriculeForName", (req, res) => {
  const { name } = req.body || {};
  const row = db.prepare("SELECT matricule FROM employes WHERE lower(nom)=lower(?)").get(name || "");
  res.json((row && row.matricule) || "");
});

// Planning
app.post("/api/getPlanning", (req, res) => {
  const { startIso, endIso } = req.body || {};
  if (!startIso || !endIso) return res.json([]);
  const rows = db.prepare(`
    SELECT date, salarie, matricule, camping, affaire, tache, debut, fin, commentaire
    FROM planning
    WHERE date BETWEEN ? AND ?
    ORDER BY date, salarie COLLATE NOCASE
  `).all(startIso, endIso);
  res.json(rows);
});
app.post("/api/savePlanning", (req, res) => {
  const entries = Array.isArray(req.body) ? req.body : [];
  const tx = db.transaction(() => {
    db.prepare("DELETE FROM planning").run();
    const ins = db.prepare(`
      INSERT INTO planning (date, salarie, matricule, camping, affaire, tache, debut, fin, commentaire)
      VALUES (?,?,?,?,?,?,?,?,?)
    `);
    entries.forEach(e => ins.run(
      e.date || "", e.salarie || "", e.matricule || "",
      e.camping || "", e.affaire || "", e.tache || "",
      e.debut || "", e.fin || "", e.commentaire || ""
    ));
  });
  tx();
  res.json({ ok: true, count: entries.length });
});
app.post("/api/getPlanningForUser", (req, res) => {
  const { loginOrMatricule, startIso, endIso } = req.body || {};
  if (!startIso || !endIso || !loginOrMatricule) return res.json([]);
  const key = String(loginOrMatricule).toLowerCase();
  const rows = db.prepare(`
    SELECT date, salarie, matricule, camping, affaire, tache, debut, fin, commentaire
    FROM planning
    WHERE date BETWEEN ? AND ?
  `).all(startIso, endIso).filter(r => {
    const nom = (r.salarie || "").toLowerCase();
    const mat = (r.matricule || "").toLowerCase();
    return nom === key || (!!mat && mat === key);
  });
  res.json(rows);
});
app.post("/api/getInitialData", (req, res) => {
  const { startIso, endIso } = req.body || {};
  const campAff = db.prepare("SELECT camping, affaire FROM camp_aff").all();
  const employes = db.prepare("SELECT nom,email,password,role,matricule FROM employes").all();
  let planning = [];
  if (startIso && endIso) {
    planning = db.prepare(`
      SELECT date, salarie, matricule, camping, affaire, tache, debut, fin, commentaire
      FROM planning
      WHERE date BETWEEN ? AND ?
    `).all(startIso, endIso);
  }
  res.json({ campAff, employes, planning });
});
app.post("/api/importCampAffLocal", (req, res) => {
  const { b64, filename } = req.body || {};
  if (!b64) return res.status(400).json({ ok:false, error:"contenu vide" });
  try {
    const buf = Buffer.from(b64, "base64");
    const wb = xlsx.read(buf, { type: "buffer" });
    const ws = wb.Sheets[wb.SheetNames[0]];
    const rows = xlsx.utils.sheet_to_json(ws, { header: 1 });

    const out = [];
    for (let i = 1; i < rows.length; i++) {
      const r = rows[i] || [];
      const camping = (r[5] || "").toString().trim();
      const a = (r[0] || "").toString().trim();
      const c = (r[2] || "").toString().trim();
      const affaire = (a || c) ? `${a}:${c}`.replace(/^:|:$/g, "") : "";
      if (!camping && !affaire) continue;
      out.push([camping, affaire]);
    }

    const tx = db.transaction(() => {
      db.prepare("DELETE FROM camp_aff").run();
      const ins = db.prepare("INSERT INTO camp_aff (camping, affaire) VALUES (?,?)");
      out.forEach(r => ins.run(r[0], r[1]));
    });
    tx();
    res.json({ ok:true, count: out.length });
  } catch (e) {
    res.status(500).json({ ok:false, error: e.message });
  }
});

// Pointages V2
app.post("/api/enregistrerPointageV2", (req, res) => {
  const payload = req.body || {};
  const name = payload.nom || "";
  const typePersonne = payload.typePersonne || "";
  const matricule = payload.matricule || "";
  const entries = Array.isArray(payload.entries) ? payload.entries : [];
  if (!name || !entries.length) return res.json({ ok:false, count:0 });

  const todayIso = new Date().toISOString().slice(0,10);
  const rows = [];
  entries.forEach(e => {
    const debut = e.heureDebut || "";
    const fin = e.heureFin || "";
    const pause = e.heurePause || "";
    const reprise = e.heureReprise || "";
    const minutes = computeDurationMinutes(debut, fin, pause, reprise);
    if (e.type === "deplacement") {
      const nature = e.dtype === "travail" ? "DEPL TRAVAIL" : "DEPL DOMICILE";
      const travail = nature === "DEPL TRAVAIL" ? minutes : 0;
      const depl = nature === "DEPL DOMICILE" ? minutes : 0;
      rows.push({
        date: todayIso,
        type_personne: typePersonne,
        nom: name,
        nature,
        camping: "",
        affaire: "",
        commentaire: e.commentaire || "",
        debut,
        pause: "",
        reprise: "",
        fin,
        travail_hhmm: minutesToHHMM(travail),
        depl_hhmm: minutesToHHMM(depl),
        matricule
      });
    } else {
      rows.push({
        date: todayIso,
        type_personne: typePersonne,
        nom: name,
        nature: "TRAVAIL",
        camping: e.camping || "",
        affaire: e.affaire || "",
        commentaire: e.commentaire || e.tache || "",
        debut,
        pause,
        reprise,
        fin,
        travail_hhmm: minutesToHHMM(minutes),
        depl_hhmm: minutesToHHMM(0),
        matricule
      });
    }
  });

  const tx = db.transaction(() => {
    const ins = db.prepare(`
      INSERT INTO pointages
      (date,type_personne,nom,nature,camping,affaire,commentaire,debut,pause,reprise,fin,travail_hhmm,depl_hhmm,matricule)
      VALUES (@date,@type_personne,@nom,@nature,@camping,@affaire,@commentaire,@debut,@pause,@reprise,@fin,@travail_hhmm,@depl_hhmm,@matricule)
    `);
    rows.forEach(r => ins.run(r));
  });
  tx();
  res.json({ ok:true, count: rows.length });
});

// Historique pointages
app.post("/api/getHistoriquePointagesFiltered", (req, res) => {
  const { dateFrom, dateTo, salarie, camping } = req.body || {};
  const rows = db.prepare("SELECT * FROM pointages ORDER BY id").all();
  const out = [];
  out.push(["Date","Type personne","Nom","Nature","Camping","Affaire","Commentaire","Début","Pause","Reprise","Fin","Travail","Déplacement","Matricule","ROW_INDEX"]);
  rows.forEach((r, i) => {
    const d = r.date;
    const okDate = (!dateFrom || d >= dateFrom) && (!dateTo || d <= dateTo);
    const okSal = !salarie || (r.nom || "").toLowerCase() === salarie.toLowerCase();
    const okCamp = !camping || (r.camping || "").toLowerCase() === camping.toLowerCase();
    if (okDate && okSal && okCamp) {
      out.push([
        r.date, r.type_personne, r.nom, r.nature, r.camping, r.affaire, r.commentaire,
        r.debut, r.pause, r.reprise, r.fin, r.travail_hhmm, r.depl_hhmm, r.matricule,
        i + 2
      ]);
    }
  });
  res.json(out);
});
app.get("/api/getHistoriquePointages", (_req, res) => {
  const rows = db.prepare("SELECT * FROM pointages ORDER BY id").all();
  const out = [];
  out.push(["Date","Type personne","Nom","Nature","Camping","Affaire","Commentaire","Début","Pause","Reprise","Fin","Travail","Déplacement","Matricule"]);
  rows.forEach(r => out.push([
    r.date, r.type_personne, r.nom, r.nature, r.camping, r.affaire, r.commentaire,
    r.debut, r.pause, r.reprise, r.fin, r.travail_hhmm, r.depl_hhmm, r.matricule
  ]));
  res.json(out);
});

// Paye / validation
app.post("/api/getPointagesAValider", (req, res) => {
  const { dateFrom, dateTo, salarie } = req.body || {};
  const rows = db.prepare("SELECT * FROM pointages ORDER BY date, nom COLLATE NOCASE").all();
  const valides = new Set(
    db.prepare("SELECT date || '|||' || salarie AS k FROM payes_validation").all().map(r => r.k)
  );
  const out = [];
  rows.forEach(r => {
    const okDate = (!dateFrom || r.date >= dateFrom) && (!dateTo || r.date <= dateTo);
    const okSal = !salarie || (r.nom || "").toLowerCase() === salarie.toLowerCase();
    const k = `${r.date}|||${r.nom || ""}`;
    if (okDate && okSal && !valides.has(k)) {
      out.push({
        date: r.date,
        salarie: r.nom,
        travailMin: hhmmToMinutes(r.travail_hhmm),
        deplacementMin: hhmmToMinutes(r.depl_hhmm)
      });
    }
  });
  res.json(out);
});
app.post("/api/validerPointage", (req, res) => {
  const p = req.body || {};
  const vals = {
    date: p.date || "",
    salarie: p.salarie || "",
    travail_hhmm: minutesToHHMM(p.travailMin || 0),
    depl_hhmm: minutesToHHMM(p.deplacementMin || 0),
    panier_midi: p.panierMidi || "Non",
    panier_soir: p.panierSoir || "Non",
    zone: p.zone || "",
    forfait_trajet: p.forfaitTrajet || "",
    hs_hhmm: minutesToHHMM(p.heuresSupMin || 0),
    hnuit_hhmm: minutesToHHMM(p.heuresNuitMin || 0),
    decouches: p.decouches || "Non",
    forfait_we: p.forfaitWeekend || "Non",
    statut: "validé",
    valide_par: p.validePar || "",
    valide_le: new Date().toISOString(),
    commentaire: p.commentaire || ""
  };
  db.prepare(`
    INSERT INTO payes_validation
    (date,salarie,travail_hhmm,depl_hhmm,panier_midi,panier_soir,zone,forfait_trajet,hs_hhmm,hnuit_hhmm,decouches,forfait_we,statut,valide_par,valide_le,commentaire)
    VALUES (@date,@salarie,@travail_hhmm,@depl_hhmm,@panier_midi,@panier_soir,@zone,@forfait_trajet,@hs_hhmm,@hnuit_hhmm,@decouches,@forfait_we,@statut,@valide_par,@valide_le,@commentaire)
  `).run(vals);
  res.json({ ok: true });
});
app.post("/api/updatePayeValidation", (req, res) => {
  const p = req.body || {};
  const stmt = db.prepare(`
    UPDATE payes_validation SET
      date=@date, salarie=@salarie, travail_hhmm=@travail_hhmm, depl_hhmm=@depl_hhmm,
      panier_midi=@panier_midi, panier_soir=@panier_soir, zone=@zone, forfait_trajet=@forfait_trajet,
      hs_hhmm=@hs_hhmm, hnuit_hhmm=@hnuit_hhmm, decouches=@decouches, forfait_we=@forfait_we,
      commentaire=@commentaire
    WHERE date=@origDate AND salarie=@origSalarie
  `);
  const r = stmt.run({
    date: p.date || p.origDate,
    salarie: p.salarie || p.origSalarie,
    travail_hhmm: minutesToHHMM(p.travailMin || 0),
    depl_hhmm: minutesToHHMM(p.deplacementMin || 0),
    panier_midi: p.panierMidi || "Non",
    panier_soir: p.panierSoir || "Non",
    zone: p.zone || "",
    forfait_trajet: p.forfaitTrajet || "",
    hs_hhmm: minutesToHHMM(p.heuresSupMin || 0),
    hnuit_hhmm: minutesToHHMM(p.heuresNuitMin || 0),
    decouches: p.decouches || "Non",
    forfait_we: p.forfaitWeekend || "Non",
    commentaire: p.commentaire || "",
    origDate: p.origDate || p.date,
    origSalarie: p.origSalarie || p.salarie
  });
  res.json({ ok: true, changes: r.changes });
});
app.post("/api/deletePayeValidation", (req, res) => {
  const { date, salarie } = req.body || {};
  const r = db.prepare("DELETE FROM payes_validation WHERE date=? AND salarie=?").run(date || "", salarie || "");
  res.json({ ok: true, changes: r.changes });
});
app.post("/api/getPayeValidee", (req, res) => {
  const { dateFrom, dateTo, salarie } = req.body || {};
  const rows = db.prepare("SELECT * FROM payes_validation ORDER BY date, salarie COLLATE NOCASE").all();
  const out = rows.filter(r =>
    (!dateFrom || r.date >= dateFrom) &&
    (!dateTo || r.date <= dateTo) &&
    (!salarie || (r.salarie || "").toLowerCase() === salarie.toLowerCase())
  ).map(r => ({
    date: r.date,
    salarie: r.salarie,
    travailMin: hhmmToMinutes(r.travail_hhmm),
    deplacementMin: hhmmToMinutes(r.depl_hhmm),
    panierMidi: r.panier_midi,
    panierSoir: r.panier_soir,
    zone: r.zone,
    forfaitTrajet: r.forfait_trajet,
    heuresSupMin: hhmmToMinutes(r.hs_hhmm),
    heuresNuitMin: hhmmToMinutes(r.hnuit_hhmm),
    decouches: r.decouches,
    forfaitWeekend: r.forfait_we,
    validePar: r.valide_par,
    valideLe: r.valide_le,
    commentaire: r.commentaire
  }));
  res.json(out);
});
app.post("/api/getRecapParSalarie", (req, res) => {
  const { dateFrom, dateTo } = req.body || {};
  const rows = db.prepare("SELECT * FROM payes_validation").all();
  const inRange = rows.filter(r =>
    (!dateFrom || r.date >= dateFrom) &&
    (!dateTo || r.date <= dateTo)
  );
  const agg = {};
  inRange.forEach(r => {
    const n = r.salarie || "";
    if (!agg[n]) agg[n] = {
      salarie: n,
      travailMin: 0, deplacementMin: 0,
      heuresSupMin: 0, heuresNuitMin: 0,
      panierMidi: 0, panierSoir: 0, decouches: 0,
      zones: {}, trajets: {}, combos: {}
    };
    const a = agg[n];
    a.travailMin += hhmmToMinutes(r.travail_hhmm);
    a.deplacementMin += hhmmToMinutes(r.depl_hhmm);
    a.heuresSupMin += hhmmToMinutes(r.hs_hhmm);
    a.heuresNuitMin += hhmmToMinutes(r.hnuit_hhmm);
    a.panierMidi += (r.panier_midi || "") === "Oui" ? 1 : 0;
    a.panierSoir += (r.panier_soir || "") === "Oui" ? 1 : 0;
    a.decouches += (r.decouches || "") === "Oui" ? 1 : 0;
    const z = (r.zone || "").trim();
    const ft = (r.forfait_trajet || "").trim();
    if (z) a.zones[z] = (a.zones[z] || 0) + hhmmToMinutes(r.depl_hhmm);
    if (ft) a.trajets[ft] = (a.trajets[ft] || 0) + hhmmToMinutes(r.depl_hhmm);
    if (z && ft) {
      const key = `${z}|||${ft}`;
      a.combos[key] = (a.combos[key] || 0) + hhmmToMinutes(r.depl_hhmm);
    }
  });
  const list = Object.values(agg).sort((a,b)=>a.salarie.localeCompare(b.salarie,'fr',{sensitivity:'base'}));
  list.allZones = []; list.allTrajets = []; list.allCombos = [];
  res.json(list);
});

// Historique edit
app.post("/api/updateHistoriquePointage", (req, res) => {
  const { rowIndex, payload } = req.body || {};
  if (!rowIndex || !payload) return res.status(400).json({ ok:false, error:"rowIndex/payload manquant" });
  const row = db.prepare("SELECT * FROM pointages ORDER BY id LIMIT 1 OFFSET ?").get(rowIndex - 2);
  if (!row) return res.status(404).json({ ok:false, error:"ligne introuvable" });

  const minutes = computeDurationMinutes(payload.debut, payload.fin, payload.pause, payload.reprise);
  const isDepl = (row.nature || "").toUpperCase().startsWith("DEPL");
  const travailMin = isDepl && (row.nature || "").toUpperCase().includes("DOMICILE") ? 0 : minutes;
  const deplMin = isDepl && (row.nature || "").toUpperCase().includes("DOMICILE") ? minutes : 0;

  db.prepare(`
    UPDATE pointages SET
      date=@date, camping=@camping, affaire=@affaire, commentaire=@commentaire,
      debut=@debut, pause=@pause, reprise=@reprise, fin=@fin,
      travail_hhmm=@travail_hhmm, depl_hhmm=@depl_hhmm
    WHERE id=@id
  `).run({
    id: row.id,
    date: payload.date || row.date,
    camping: payload.camping || "",
    affaire: payload.affaire || "",
    commentaire: payload.commentaire || "",
    debut: payload.debut || "",
    pause: payload.pause || "",
    reprise: payload.reprise || "",
    fin: payload.fin || "",
    travail_hhmm: minutesToHHMM(travailMin),
    depl_hhmm: minutesToHHMM(deplMin)
  });
  res.json({ ok:true });
});
app.post("/api/deleteHistoriquePointage", (req,res)=>{
  const { rowIndex } = req.body || {};
  if (!rowIndex) return res.status(400).json({ ok:false, error:"rowIndex manquant" });
  const row = db.prepare("SELECT * FROM pointages ORDER BY id LIMIT 1 OFFSET ?").get(rowIndex - 2);
  if (!row) return res.status(404).json({ ok:false, error:"ligne introuvable" });
  db.prepare("DELETE FROM pointages WHERE id=?").run(row.id);
  res.json({ ok:true });
});

// Start
app.listen(PORT, () => {
  console.log(`API SQLite prête sur port ${PORT}`);
});

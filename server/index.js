import express from "express";
import { DatabaseSync } from "node:sqlite";
import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { mkdirSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { seedData } from "./seed.js";
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const roles = [
  "Admin",
  "Doctor",
  "Pharmacist",
  "Lab technician",
  "Pathologist",
];
const all = [
  "patients",
  "doctors",
  "appointments",
  "medicines",
  "batches",
  "catalog",
  "suppliers",
  "labs",
  "consultations",
  "prescriptions",
  "invoices",
  "purchases",
  "returns",
  "ledger",
  "communications",
  "settings",
  "audit",
  "users",
  "purchaseOrders",
  "transfers",
  "imaging",
];
const prefix = {
  patients: "PT",
  doctors: "DR",
  appointments: "APT",
  medicines: "MED",
  batches: "BAT",
  catalog: "TEST",
  suppliers: "SUP",
  labs: "LAB",
  consultations: "CON",
  prescriptions: "RX",
  invoices: "INV",
  purchases: "PUR",
  returns: "RET",
  ledger: "STK",
  communications: "MSG",
  audit: "EVT",
  users: "USR",
  purchaseOrders: "PO",
  transfers: "TRF",
  imaging: "IMG",
  attachments: "ATT",
};
const permissions = {
  Admin: all,
  Doctor: [
    "patients",
    "appointments",
    "consultations",
    "prescriptions",
    "labs",
    "imaging",
  ],
  Pharmacist: [
    "prescriptions",
    "medicines",
    "batches",
    "suppliers",
    "purchases",
    "returns",
    "invoices",
    "purchaseOrders",
    "transfers",
  ],
  "Lab technician": ["labs", "catalog"],
  Pathologist: ["labs", "catalog"],
};
const fail = (m, status = 400) => Object.assign(new Error(m), { status });
const hash = (p, s) => scryptSync(p, s, 64).toString("hex");
const publicUser = ({ passwordHash, salt, ...u }) => u;
const date = () =>
  new Date().toLocaleDateString("en-CA", { timeZone: "Asia/Kolkata" });
const number = (v, label, min = 0) => {
  const n = Number(v);
  if (!Number.isFinite(n) || n < min)
    throw fail(`${label} must be at least ${min}`);
  return n;
};
const qty = (v) => {
  const n = number(v, "Quantity", 1);
  if (!Number.isInteger(n)) throw fail("Quantity must be a whole number");
  return n;
};
const validDate = (v) => {
  if (typeof v !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(v)) return false;
  const parsed = new Date(v + "T00:00:00Z");
  return (
    Number.isFinite(parsed.getTime()) && parsed.toISOString().slice(0, 10) === v
  );
};
export function createApp({
  dbPath = process.env.DB_PATH || path.join(root, "data", "dyvora.sqlite"),
  demo = process.env.DEMO_MODE !== "false",
} = {}) {
  if (dbPath !== ":memory:")
    mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new DatabaseSync(dbPath);
  db.exec(
    "PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS records(collection TEXT NOT NULL,id TEXT NOT NULL,data TEXT NOT NULL,PRIMARY KEY(collection,id)); CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,userId TEXT NOT NULL,expires INTEGER NOT NULL);",
  );
  const get = (c, id) => {
    const r = db
      .prepare("SELECT data FROM records WHERE collection=? AND id=?")
      .get(c, id);
    return r ? JSON.parse(r.data) : null;
  };
  const list = (c) =>
    db
      .prepare("SELECT data FROM records WHERE collection=? ORDER BY rowid")
      .all(c)
      .map((r) => JSON.parse(r.data));
  const save = (c, r) => {
    db.prepare(
      "INSERT INTO records VALUES(?,?,?) ON CONFLICT(collection,id) DO UPDATE SET data=excluded.data",
    ).run(c, r.id, JSON.stringify(r));
    return r;
  };
  const make = (c, data) =>
    save(c, {
      ...data,
      id: `${prefix[c]}-${randomBytes(4).toString("hex").toUpperCase()}`,
      createdAt: new Date().toISOString(),
    });
  const tx = (fn) => {
    db.exec("BEGIN IMMEDIATE");
    try {
      const out = fn();
      db.exec("COMMIT");
      return out;
    } catch (e) {
      db.exec("ROLLBACK");
      throw e;
    }
  };
  const audit = (u, action, ref) =>
    make("audit", { actor: u.name, role: u.role, action, reference: ref });
  const need = (c, id) => {
    const r = get(c, id);
    if (!r) throw fail(`${c} record not found`, 404);
    return r;
  };
  if (!list("users").length) {
    if (demo) {
      for (const [c, rs] of Object.entries(seedData()))
        for (const r of rs) save(c, r);
    }
    const password = process.env.ADMIN_PASSWORD || (demo ? "Dyvora@2026" : "");
    if (!password) throw Error("Set ADMIN_PASSWORD when DEMO_MODE=false");
    for (const [i, role] of (demo ? roles : ["Admin"]).entries()) {
      const salt = randomBytes(16).toString("hex");
      save("users", {
        id: `USR-${i + 1}`,
        name: [
          "Rohit Sharma",
          "Dr. Aditi Verma",
          "Rahul Sharma",
          "Ravi Singh",
          "Dr. Sana Khan",
        ][i],
        role,
        email:
          ["admin", "doctor", "pharmacy", "lab", "pathologist"][i] +
          "@dyvora.local",
        doctorId: role === "Doctor" ? "DR-101" : undefined,
        status: "Active",
        salt,
        passwordHash: hash(password, salt),
      });
    }
    if (!demo)
      save("settings", {
        id: "clinic",
        name: "Dyvora Clinic",
        currency: "INR",
        timezone: "Asia/Kolkata",
      });
  }
  const app = express();
  app.set("trust proxy", 1);
  app.disable("x-powered-by");
  app.use(express.json({ limit: "8mb" }));
  app.use((req, res, next) => {
    res.set({
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "same-origin",
      "X-Frame-Options": "DENY",
    });
    const host = req.get("host");
    const origin = req.headers.origin;
    const sameOrigin =
      !origin ||
      origin === `${req.protocol}://${host}` ||
      origin === `https://${host}` ||
      origin === `http://${host}` ||
      /^http:\/\/(localhost|127\.0\.0\.1):(5173|4000)$/.test(origin);
    if (req.method !== "GET" && !sameOrigin)
      return res.status(403).json({ error: "Origin not allowed" });
    next();
  });
  app.get("/api/health", (req, res) => res.json({ status: "ok", demo }));
  const attempts = new Map();
  app.post("/api/auth/login", (req, res, next) => {
    try {
      const key = req.ip;
      const a = attempts.get(key) || { count: 0, until: Date.now() + 600000 };
      if (a.until < Date.now()) {
        a.count = 0;
        a.until = Date.now() + 600000;
      }
      if (a.count >= 20) throw fail("Too many attempts. Try again later.", 429);
      const u = list("users").find(
        (u) => u.email.toLowerCase() === String(req.body.email).toLowerCase(),
      );
      if (
        !u ||
        u.status !== "Active" ||
        !timingSafeEqual(
          Buffer.from(u.passwordHash, "hex"),
          Buffer.from(hash(String(req.body.password), u.salt), "hex"),
        )
      ) {
        a.count++;
        attempts.set(key, a);
        throw fail("Email or password is incorrect", 401);
      }
      attempts.delete(key);
      const token = randomBytes(32).toString("hex");
      db.prepare("INSERT INTO sessions VALUES(?,?,?)").run(
        token,
        u.id,
        Date.now() + 8 * 3600000,
      );
      res.cookie("dyvora_session", token, {
        httpOnly: true,
        sameSite: "strict",
        secure: process.env.SECURE_COOKIE === "true",
        maxAge: 8 * 3600000,
      });
      res.json({ user: publicUser(u), demo });
    } catch (e) {
      next(e);
    }
  });
  app.use("/api", (req, res, next) => {
    const token = (req.headers.cookie || "")
      .split(";")
      .map((s) => s.trim())
      .find((s) => s.startsWith("dyvora_session="))
      ?.split("=")[1];
    const s =
      token &&
      db
        .prepare("SELECT * FROM sessions WHERE token=? AND expires>?")
        .get(token, Date.now());
    const u = s && get("users", s.userId);
    if (!u || u.status !== "Active")
      return res.status(401).json({ error: "Please sign in" });
    req.user = u;
    req.token = token;
    next();
  });
  app.get("/api/auth/me", (req, res) =>
    res.json({ user: publicUser(req.user), demo }),
  );
  app.post("/api/auth/logout", (req, res) => {
    db.prepare("DELETE FROM sessions WHERE token=?").run(req.token);
    res.clearCookie("dyvora_session");
    res.json({ ok: true });
  });
  const can = (u, c) => permissions[u.role]?.includes(c);
  app.get("/api/bootstrap", (req, res) => {
    const data = {};
    const readable = {
      Doctor: [
        "patients",
        "doctors",
        "appointments",
        "medicines",
        "batches",
        "catalog",
        "labs",
        "consultations",
        "prescriptions",
        "settings",
        "imaging",
      ],
      Pharmacist: [
        "patients",
        "doctors",
        "medicines",
        "batches",
        "catalog",
        "suppliers",
        "prescriptions",
        "invoices",
        "purchases",
        "returns",
        "ledger",
        "settings",
        "purchaseOrders",
        "transfers",
      ],
      "Lab technician": ["patients", "doctors", "catalog", "labs", "settings"],
      Pathologist: ["patients", "doctors", "catalog", "labs", "settings"],
    };
    for (const c of all) {
      if (req.user.role !== "Admin" && !readable[req.user.role]?.includes(c)) {
        data[c] = [];
        continue;
      }
      if (c === "users")
        data[c] = req.user.role === "Admin" ? list(c).map(publicUser) : [];
      else if (
        ["audit", "communications", "settings"].includes(c) &&
        req.user.role !== "Admin"
      )
        data[c] = c === "settings" ? list(c) : [];
      else data[c] = list(c);
    }
    res.json({ data, user: publicUser(req.user), demo });
  });
  app.post("/api/attachments", (req, res, next) => {
    try {
      const b = req.body;
      if (
        !["labs", "imaging"].includes(b.collection) ||
        !can(req.user, b.collection) ||
        (req.user.role === "Doctor" && b.collection === "labs")
      )
        throw fail("Report attachment access denied", 403);
      const record = need(b.collection, b.recordId);
      if (
        (b.collection === "labs" &&
          ["Verified", "Released"].includes(record.status)) ||
        (b.collection === "imaging" && record.status === "Reviewed")
      )
        throw fail("Finalized reports cannot be replaced");
      const file = Buffer.from(String(b.content || ""), "base64");
      if (!file.length || file.length > 5 * 1024 * 1024)
        throw fail("Choose a report under 5 MB");
      const mime =
        file.subarray(0, 5).toString() === "%PDF-"
          ? "application/pdf"
          : file[0] === 0xff && file[1] === 0xd8
            ? "image/jpeg"
            : file
                  .subarray(0, 8)
                  .equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))
              ? "image/png"
              : null;
      if (!mime) throw fail("Only PDF, PNG or JPEG reports are supported");
      const a = make("attachments", {
        name: path.basename(String(b.name)).replace(/[^a-zA-Z0-9._ -]/g, "_"),
        mime,
        content: file.toString("base64"),
        collection: b.collection,
        recordId: b.recordId,
      });
      save(b.collection, {
        ...record,
        attachmentId: a.id,
        attachmentName: a.name,
      });
      audit(req.user, "Attached report", record.id);
      res.status(201).json({ id: a.id, name: a.name });
    } catch (e) {
      next(e);
    }
  });
  app.get("/api/attachments/:id", (req, res, next) => {
    try {
      const a = need("attachments", req.params.id);
      if (
        !["Admin", "Doctor", "Lab technician", "Pathologist"].includes(
          req.user.role,
        ) ||
        (a.collection === "imaging" &&
          !["Admin", "Doctor"].includes(req.user.role))
      )
        throw fail("Report access denied", 403);
      res
        .set({
          "Content-Type": a.mime,
          "Content-Disposition": 'inline; filename="' + a.name + '"',
          "Content-Security-Policy": "sandbox; default-src 'none'",
          "Cache-Control": "no-store",
        })
        .send(Buffer.from(a.content, "base64"));
    } catch (e) {
      next(e);
    }
  });
  app.post("/api/:collection", (req, res, next) => {
    try {
      const c = req.params.collection;
      if (!all.includes(c) || !can(req.user, c))
        throw fail("Your role cannot create this record", 403);
      if (
        [
          "audit",
          "ledger",
          "returns",
          "purchases",
          "prescriptions",
          "consultations",
          "settings",
          "transfers",
        ].includes(c)
      )
        throw fail("Use the workflow action for this record");
      const fields = {
        patients: [
          "name",
          "age",
          "gender",
          "phone",
          "bloodGroup",
          "allergies",
          "address",
        ],
        doctors: ["name", "specialty", "phone", "fee", "status"],
        appointments: [
          "patientId",
          "doctorId",
          "date",
          "time",
          "type",
          "reason",
        ],
        medicines: [
          "name",
          "category",
          "unit",
          "manufacturer",
          "price",
          "gst",
          "reorderLevel",
          "salePolicy",
        ],
        batches: [
          "medicineId",
          "batchNo",
          "expiry",
          "quantity",
          "cost",
          "location",
          "supplierId",
        ],
        catalog: ["name", "code", "sample", "price", "unit", "reference"],
        suppliers: ["name", "contact", "phone", "email", "gst", "status"],
        labs: ["patientId", "doctorId", "testIds", "priority", "notes"],
        invoices: ["patientId", "items"],
        users: ["name", "email", "role", "doctorId", "password"],
        communications: ["patientId", "channel", "message"],
        purchaseOrders: ["supplierId", "items", "notes"],
        imaging: [
          "patientId",
          "doctorId",
          "modality",
          "bodyPart",
          "performedAt",
          "reportingClinician",
          "reportText",
        ],
      };
      const b = Object.fromEntries(
        Object.entries(req.body).filter(([k]) => fields[c]?.includes(k)),
      );
      const result = tx(() => {
        if (c === "patients") {
          if (!b.name?.trim() || !b.phone?.trim())
            throw fail("Patient name and phone are required");
          b.age = number(b.age, "Age");
          if (b.age > 130) throw fail("Check patient age");
        }
        if (c === "doctors") {
          if (!b.name || !b.specialty)
            throw fail("Doctor name and specialty required");
          b.fee = number(b.fee, "Fee");
        }
        if (c === "appointments") {
          need("patients", b.patientId);
          need("doctors", b.doctorId);
          if (!validDate(b.date) || !/^([01]\d|2[0-3]):[0-5]\d$/.test(b.time))
            throw fail("Date and time required");
          if (
            list(c).some(
              (a) =>
                a.doctorId === b.doctorId &&
                a.date === b.date &&
                a.time === b.time &&
                a.status !== "Cancelled",
            )
          )
            throw fail("Doctor already has an appointment at this time");
          b.token =
            Math.max(
              0,
              ...list(c)
                .filter((a) => a.date === b.date)
                .map((a) => a.token),
            ) + 1;
          b.status = "Scheduled";
        }
        if (c === "medicines") {
          if (!b.name) throw fail("Medicine name required");
          b.price = number(b.price, "Price");
          b.reorderLevel = number(b.reorderLevel, "Reorder level");
          b.gst = number(b.gst || 0, "Tax");
          if (b.gst > 100) throw fail("Tax must be 0–100");
        }
        if (c === "batches") {
          need("medicines", b.medicineId);
          b.quantity = qty(b.quantity);
          b.cost = number(b.cost, "Cost");
          if (!b.batchNo || !validDate(b.expiry) || b.expiry <= date())
            throw fail("Batch number and future expiry required");
        }
        if (c === "labs") {
          need("patients", b.patientId);
          need("doctors", b.doctorId);
          if (!Array.isArray(b.testIds) || !b.testIds.length)
            throw fail("Select at least one test");
          b.testIds = [...new Set(b.testIds)];
          b.amount = b.testIds.reduce(
            (s, id) => s + need("catalog", id).price,
            0,
          );
          b.status = "Ordered";
          b.results = "";
          b.date = date();
        }
        if (c === "catalog") {
          if (!b.name) throw fail("Test name required");
          b.price = number(b.price, "Price");
        }
        if (c === "imaging") {
          need("patients", b.patientId);
          need("doctors", b.doctorId);
          if (
            !b.modality ||
            !b.reportText?.trim() ||
            !b.reportingClinician?.trim()
          )
            throw fail(
              "Modality, reporting clinician and transcribed findings are required",
            );
          b.status = "Awaiting review";
        }
        if (c === "purchaseOrders") {
          need("suppliers", b.supplierId);
          if (!Array.isArray(b.items) || !b.items.length)
            throw fail("Add purchase order items");
          b.items = b.items.map((i) => ({
            medicineId: need("medicines", i.medicineId).id,
            quantity: qty(i.quantity),
            cost: number(i.cost, "Cost"),
          }));
          b.amount = b.items.reduce((s, i) => s + i.quantity * i.cost, 0);
          b.status = "Ordered";
        }
        if (c === "suppliers" && !b.name) throw fail("Supplier name required");
        if (c === "users" && b.role === "Doctor") need("doctors", b.doctorId);
        if (c === "invoices") {
          need("patients", b.patientId);
          if (!Array.isArray(b.items) || !b.items.length)
            throw fail("Add invoice items");
          b.items = b.items.map((i) => ({
            description: String(i.description),
            quantity: qty(i.quantity),
            price: number(i.price, "Price"),
          }));
          b.amount =
            Math.round(
              b.items.reduce((s, i) => s + i.price * i.quantity, 0) * 100,
            ) / 100;
          b.paid = 0;
          b.status = "Unpaid";
        }
        if (c === "users") {
          if (
            !roles.includes(b.role) ||
            !b.email ||
            !b.name ||
            String(b.password).length < 10
          )
            throw fail(
              "Name, email, role and password of at least 10 characters required",
            );
          if (list(c).some((u) => u.email === b.email))
            throw fail("Email already exists");
          b.salt = randomBytes(16).toString("hex");
          b.passwordHash = hash(b.password, b.salt);
          delete b.password;
          b.status = "Active";
        }
        if (c === "communications") {
          if (!b.message?.trim()) throw fail("Message required");
          b.status = "Draft — provider not connected";
        }
        const r = make(c, b);
        if (c === "labs") {
          make("invoices", {
            patientId: b.patientId,
            labId: r.id,
            items: b.testIds.map((id) => {
              const t = need("catalog", id);
              return { description: t.name, quantity: 1, price: t.price };
            }),
            amount: b.amount,
            paid: 0,
            status: "Unpaid",
          });
        }
        if (c === "batches")
          make("ledger", {
            medicine: need("medicines", b.medicineId).name,
            batch: b.batchNo,
            type: "Opening stock",
            quantity: b.quantity,
            reference: r.id,
          });
        audit(req.user, `Created ${c}`, r.id);
        return c === "users" ? publicUser(r) : r;
      });
      res.status(201).json(result);
    } catch (e) {
      next(e);
    }
  });
  app.patch("/api/:collection/:id", (req, res, next) => {
    try {
      const { collection: c, id } = req.params;
      if (!can(req.user, c))
        throw fail("Your role cannot edit this record", 403);
      if (
        ![
          "patients",
          "doctors",
          "medicines",
          "suppliers",
          "catalog",
          "settings",
          "users",
        ].includes(c)
      )
        throw fail("Use the workflow action");
      const old = need(c, id);
      const b = { ...req.body };
      for (const key of ["id", "createdAt", "passwordHash", "salt", "password"])
        delete b[key];
      if (c === "users") {
        if (
          id === req.user.id &&
          (b.status === "Inactive" || (b.role && b.role !== "Admin"))
        )
          throw fail("You cannot disable your own administrator account");
        if (b.role && !roles.includes(b.role)) throw fail("Unknown role");
      }
      if (c === "medicines" || c === "catalog")
        b.price = number(b.price ?? old.price, "Price");
      if (c === "doctors") b.fee = number(b.fee ?? old.fee, "Fee");
      if (c === "patients" && b.age !== undefined) b.age = number(b.age, "Age");
      if (
        [
          "patients",
          "doctors",
          "medicines",
          "suppliers",
          "catalog",
          "settings",
          "users",
        ].includes(c) &&
        b.name !== undefined &&
        !String(b.name).trim()
      )
        throw fail("Name is required");
      if (c === "patients") {
        const age = number(b.age ?? old.age, "Age");
        if (age > 130) throw fail("Check patient age");
        if (!String(b.phone ?? old.phone ?? "").trim())
          throw fail("Patient phone is required");
        if (b.gender && !["Female", "Male", "Other"].includes(b.gender))
          throw fail("Invalid gender");
      }
      if (c === "medicines") {
        b.reorderLevel = number(
          b.reorderLevel ?? old.reorderLevel,
          "Reorder level",
        );
        b.gst = number(b.gst ?? old.gst ?? 0, "Tax");
        if (b.gst > 100) throw fail("Tax must be 0-100");
        if (
          b.salePolicy &&
          !["Prescription required", "Non-prescription"].includes(b.salePolicy)
        )
          throw fail("Invalid sale policy");
      }
      if (c === "users") {
        if (b.role === "Doctor" || (old.role === "Doctor" && !b.role))
          need("doctors", b.doctorId ?? old.doctorId);
        if (b.status && !["Active", "Inactive"].includes(b.status))
          throw fail("Invalid account status");
        if (
          b.email &&
          list("users").some(
            (x) =>
              x.id !== id && x.email.toLowerCase() === b.email.toLowerCase(),
          )
        )
          throw fail("Email already exists");
      }
      const r = save(c, { ...old, ...b });
      audit(req.user, `Updated ${c}`, id);
      res.json(c === "users" ? publicUser(r) : r);
    } catch (e) {
      next(e);
    }
  });
  app.post("/api/actions/:action", (req, res, next) => {
    try {
      const b = req.body,
        u = req.user;
      const allow = (c) => {
        if (!can(u, c)) throw fail("Your role cannot perform this action", 403);
      };
      const result = tx(() => {
        switch (req.params.action) {
          case "appointment": {
            allow("appointments");
            const a = need("appointments", b.id);
            const transitions = {
              Scheduled: ["Waiting", "Cancelled"],
              Waiting: ["In consultation", "Cancelled"],
              "In consultation": ["Completed"],
            };
            if (!transitions[a.status]?.includes(b.status))
              throw fail("Invalid appointment transition");
            if (u.role === "Doctor" && u.doctorId !== a.doctorId)
              throw fail("This appointment is assigned to another doctor", 403);
            return save("appointments", { ...a, status: b.status });
          }
          case "consult": {
            allow("consultations");
            need("patients", b.patientId);
            need("doctors", b.doctorId);
            if (u.role === "Doctor" && u.doctorId !== b.doctorId)
              throw fail("Select your assigned doctor profile", 403);
            if (!b.complaint?.trim() || !b.diagnosis?.trim())
              throw fail("Complaint and clinician assessment are required");
            if (
              b.appointmentId &&
              list("consultations").some(
                (c) => c.appointmentId === b.appointmentId,
              )
            )
              throw fail("This visit already has a signed consultation");
            const c = make("consultations", {
              patientId: b.patientId,
              doctorId: b.doctorId,
              appointmentId: b.appointmentId,
              complaint: b.complaint,
              vitals: b.vitals,
              diagnosis: b.diagnosis,
              notes: b.notes,
              status: "Signed",
            });
            if (b.items?.length) {
              if (
                new Set(b.items.map((i) => i.medicineId)).size !==
                b.items.length
              )
                throw fail(
                  "Combine duplicate medicines into one prescription item",
                );
              for (const i of b.items) {
                need("medicines", i.medicineId);
                qty(i.quantity);
                if (!i.instructions?.trim())
                  throw fail("Prescription instructions are required");
              }
              make("prescriptions", {
                patientId: b.patientId,
                doctorId: b.doctorId,
                consultationId: c.id,
                items: b.items,
                status: "Pending",
                notes: b.notes,
              });
            }
            const doctor = need("doctors", b.doctorId);
            make("invoices", {
              patientId: b.patientId,
              consultationId: c.id,
              items: [
                {
                  description: "Consultation - " + doctor.name,
                  quantity: 1,
                  price: doctor.fee,
                },
              ],
              amount: doctor.fee,
              paid: 0,
              status: doctor.fee ? "Unpaid" : "Paid",
            });
            if (b.appointmentId) {
              const a = need("appointments", b.appointmentId);
              if (
                a.patientId !== b.patientId ||
                a.doctorId !== b.doctorId ||
                a.status !== "In consultation"
              )
                throw fail(
                  "Start this patient consultation from the queue first",
                );
              save("appointments", { ...a, status: "Completed" });
            }
            return c;
          }
          case "lab": {
            allow("labs");
            if (u.role === "Doctor")
              throw fail("Laboratory staff access required", 403);
            const l = need("labs", b.id);
            const transitions = {
              Ordered: "Sample collected",
              "Sample collected": "Processing",
              Processing: "Pending approval",
              "Pending approval": "Verified",
              Verified: "Released",
            };
            if (b.status !== transitions[l.status])
              throw fail("Invalid laboratory transition");
            if (
              ["Verified", "Released"].includes(b.status) &&
              !["Admin", "Pathologist"].includes(u.role)
            )
              throw fail("Pathologist approval required", 403);
            if (b.status === "Pending approval" && !b.results?.trim())
              throw fail("Enter results before submitting for approval");
            return save("labs", {
              ...l,
              status: b.status,
              ...(b.results ? { results: b.results } : {}),
              ...(b.status === "Sample collected"
                ? {
                    sampleId: `SMP-${randomBytes(4).toString("hex").toUpperCase()}`,
                  }
                : {}),
              ...(["Verified", "Released"].includes(b.status)
                ? { verifiedBy: u.name, verifiedAt: new Date().toISOString() }
                : {}),
            });
          }
          case "pos": {
            allow("invoices");
            need("patients", b.patientId);
            if (
              !b.items?.length ||
              new Set(b.items.map((i) => i.medicineId)).size !== b.items.length
            )
              throw fail("Add unique medicines to the sale");
            const invoice = make("invoices", {
              patientId: b.patientId,
              saleType: "Counter sale",
              items: [],
              amount: 0,
              paid: 0,
              status: "Unpaid",
              allocations: [],
            });
            const items = [],
              allocations = [];
            for (const item of b.items) {
              const m = need("medicines", item.medicineId);
              if (m.salePolicy !== "Non-prescription")
                throw fail(
                  m.name +
                    " requires a signed prescription; use prescription dispensing",
                );
              let remaining = qty(item.quantity);
              for (const batch of list("batches")
                .filter(
                  (x) =>
                    x.medicineId === m.id &&
                    x.expiry > date() &&
                    x.quantity > 0,
                )
                .sort((a, b) => a.expiry.localeCompare(b.expiry))) {
                const take = Math.min(remaining, batch.quantity);
                save("batches", { ...batch, quantity: batch.quantity - take });
                allocations.push({
                  batchId: batch.id,
                  medicineId: m.id,
                  quantity: take,
                });
                make("ledger", {
                  medicine: m.name,
                  batch: batch.batchNo,
                  type: "Counter sale",
                  quantity: -take,
                  reference: invoice.id,
                });
                remaining -= take;
                if (!remaining) break;
              }
              if (remaining)
                throw fail("Insufficient unexpired stock for " + m.name);
              items.push({
                medicineId: m.id,
                description: m.name,
                quantity: Number(item.quantity),
                price: m.price,
                tax: Number(m.gst) || 0,
              });
            }
            const amount =
              Math.round(
                items.reduce(
                  (s, i) => s + i.price * i.quantity * (1 + i.tax / 100),
                  0,
                ) * 100,
              ) / 100;
            return save("invoices", { ...invoice, items, allocations, amount });
          }
          case "dispense": {
            allow("prescriptions");
            const r = need("prescriptions", b.id);
            if (r.status !== "Pending")
              throw fail("Prescription already processed");
            const items = [];
            const allocations = [];
            for (const i of r.items) {
              const m = need("medicines", i.medicineId);
              let remaining = qty(i.quantity);
              const batches = list("batches")
                .filter((x) => x.medicineId === m.id && x.expiry > date())
                .sort((a, b) => a.expiry.localeCompare(b.expiry));
              for (const batch of batches) {
                const take = Math.min(remaining, batch.quantity);
                if (take) {
                  save("batches", {
                    ...batch,
                    quantity: batch.quantity - take,
                  });
                  allocations.push({
                    batchId: batch.id,
                    medicineId: m.id,
                    quantity: take,
                  });
                  make("ledger", {
                    medicine: m.name,
                    batch: batch.batchNo,
                    type: "Dispense",
                    quantity: -take,
                    reference: r.id,
                  });
                  remaining -= take;
                }
                if (!remaining) break;
              }
              if (remaining)
                throw fail(`Insufficient unexpired stock for ${m.name}`);
              items.push({
                description: m.name,
                medicineId: m.id,
                quantity: i.quantity,
                price: m.price,
                tax: m.gst || 0,
              });
            }
            const amount =
              Math.round(
                items.reduce(
                  (s, i) => s + i.price * i.quantity * (1 + i.tax / 100),
                  0,
                ) * 100,
              ) / 100;
            const invoice = make("invoices", {
              patientId: r.patientId,
              items,
              amount,
              paid: 0,
              status: "Unpaid",
              prescriptionId: r.id,
              allocations,
            });
            save("prescriptions", {
              ...r,
              status: "Dispensed",
              invoiceId: invoice.id,
              dispensedBy: u.name,
            });
            return invoice;
          }
          case "purchase": {
            allow("purchases");
            need("suppliers", b.supplierId);
            if (!b.invoiceNo || !b.items?.length)
              throw fail("Supplier invoice and at least one item required");
            if (
              list("purchases").some(
                (p) =>
                  p.supplierId === b.supplierId && p.invoiceNo === b.invoiceNo,
              )
            )
              throw fail("Supplier invoice already recorded");
            if (b.purchaseOrderId) {
              const po = need("purchaseOrders", b.purchaseOrderId);
              if (po.status !== "Ordered" || po.supplierId !== b.supplierId)
                throw fail(
                  "Purchase order must be open and match the supplier",
                );
              const expected = new Map(),
                actual = new Map();
              for (const item of po.items)
                expected.set(
                  item.medicineId,
                  (expected.get(item.medicineId) || 0) + Number(item.quantity),
                );
              for (const item of b.items)
                actual.set(
                  item.medicineId,
                  (actual.get(item.medicineId) || 0) + Number(item.quantity),
                );
              if (
                expected.size !== actual.size ||
                [...expected].some(([id, q]) => actual.get(id) !== q)
              )
                throw fail("Receive the complete purchase order quantities");
              save("purchaseOrders", { ...po, status: "Received" });
            }
            let amount = 0;
            const purchase = make("purchases", {
              supplierId: b.supplierId,
              invoiceNo: b.invoiceNo,
              purchaseOrderId: b.purchaseOrderId,
              status: "Received",
              items: b.items,
            });
            for (const i of b.items) {
              const m = need("medicines", i.medicineId),
                q = qty(i.quantity),
                cost = number(i.cost, "Cost");
              if (!validDate(i.expiry) || i.expiry <= date() || !i.batchNo)
                throw fail("Valid batch and future expiry required");
              amount += q * cost;
              make("batches", {
                medicineId: m.id,
                batchNo: i.batchNo,
                quantity: q,
                cost,
                expiry: i.expiry,
                supplierId: b.supplierId,
                location: "Main pharmacy",
              });
              make("ledger", {
                medicine: m.name,
                batch: i.batchNo,
                type: "Purchase",
                quantity: q,
                reference: purchase.id,
              });
            }
            return save("purchases", {
              ...purchase,
              amount: Math.round(amount * 100) / 100,
            });
          }
          case "imaging": {
            allow("imaging");
            const r = need("imaging", b.id);
            if (r.status === "Reviewed")
              throw fail("This report has already been reviewed");
            if (u.role === "Doctor" && u.doctorId !== r.doctorId)
              throw fail("Report assigned to a different doctor", 403);
            if (!b.note?.trim()) throw fail("Enter clinician review notes");
            return save("imaging", {
              ...r,
              status: "Reviewed",
              reviewNote: b.note,
              reviewedBy: u.name,
              reviewedAt: new Date().toISOString(),
            });
          }
          case "transfer": {
            allow("transfers");
            const source = need("batches", b.id),
              q = qty(b.quantity);
            if (
              q > source.quantity ||
              !b.destination?.trim() ||
              b.destination === source.location
            )
              throw fail(
                "Choose a different destination and available quantity",
              );
            save("batches", { ...source, quantity: source.quantity - q });
            const target = make("batches", {
              medicineId: source.medicineId,
              batchNo: source.batchNo,
              expiry: source.expiry,
              quantity: q,
              cost: source.cost,
              location: b.destination,
              supplierId: source.supplierId,
            });
            const r = make("transfers", {
              medicineId: source.medicineId,
              batchNo: source.batchNo,
              from: source.location,
              to: b.destination,
              quantity: q,
              sourceId: source.id,
              targetId: target.id,
            });
            make("ledger", {
              medicine: need("medicines", source.medicineId).name,
              batch: source.batchNo,
              type: "Transfer out",
              quantity: -q,
              reference: r.id,
            });
            make("ledger", {
              medicine: need("medicines", source.medicineId).name,
              batch: source.batchNo,
              type: "Transfer in",
              quantity: q,
              reference: r.id,
            });
            return r;
          }
          case "refund": {
            allow("invoices");
            const i = need("invoices", b.id),
              amount = number(b.amount, "Refund", 0.01);
            if (amount > (i.refundDue || 0))
              throw fail("Refund exceeds credited overpayment");
            if (!["Cash", "UPI", "Card", "Bank transfer"].includes(b.method))
              throw fail("Choose refund method");
            const paid = Math.round((i.paid - amount) * 100) / 100;
            return save("invoices", {
              ...i,
              paid,
              refunded: (i.refunded || 0) + amount,
              refundDue: Math.round(((i.refundDue || 0) - amount) * 100) / 100,
              refundMethod: b.method,
            });
          }
          case "purchaseOrder": {
            allow("purchaseOrders");
            const p = need("purchaseOrders", b.id);
            if (p.status !== "Ordered" || b.status !== "Cancelled")
              throw fail("Only open purchase orders may be cancelled");
            return save("purchaseOrders", { ...p, status: "Cancelled" });
          }
          case "adjust": {
            allow("batches");
            const batch = need("batches", b.id);
            const delta = Number(b.quantity);
            if (
              !Number.isInteger(delta) ||
              !delta ||
              batch.quantity + delta < 0 ||
              !b.reason?.trim()
            )
              throw fail("Valid stock adjustment and reason required");
            save("batches", { ...batch, quantity: batch.quantity + delta });
            return make("ledger", {
              medicine: need("medicines", batch.medicineId).name,
              batch: batch.batchNo,
              type: "Adjustment",
              quantity: delta,
              reference: b.reason,
              actor: u.name,
            });
          }
          case "payment": {
            allow("invoices");
            const i = need("invoices", b.id),
              amount = number(b.amount, "Payment", 0.01);
            if (!["Cash", "UPI", "Card", "Bank transfer"].includes(b.method))
              throw fail("Choose a payment method");
            if (
              amount >
              Math.round((i.amount - (i.credit || 0) - i.paid) * 100) / 100
            )
              throw fail("Payment exceeds outstanding balance");
            const paid = Math.round((i.paid + amount) * 100) / 100;
            return save("invoices", {
              ...i,
              paid,
              method: b.method,
              status: paid >= i.amount - (i.credit || 0) ? "Paid" : "Part paid",
            });
          }
          case "return": {
            allow("returns");
            const i = need("invoices", b.invoiceId);
            if (!i.prescriptionId && i.saleType !== "Counter sale")
              throw fail("Only pharmacy invoices can be returned here");
            const item = i.items.find((x) => x.medicineId === b.medicineId);
            if (!item || !b.reason?.trim())
              throw fail("Select medicine and return reason");
            const q = qty(b.quantity);
            const returned = list("returns")
              .filter(
                (r) => r.invoiceId === i.id && r.medicineId === b.medicineId,
              )
              .reduce((s, r) => s + r.quantity, 0);
            if (q + returned > item.quantity)
              throw fail("Return exceeds dispensed quantity");
            const amount =
              Math.round(q * item.price * (1 + (item.tax || 0) / 100) * 100) /
              100;
            const r = make("returns", {
              invoiceId: i.id,
              patientId: i.patientId,
              medicineId: b.medicineId,
              quantity: q,
              amount,
              reason: b.reason,
              status: "Quarantined",
              restocked: false,
            });
            const totalReturned = list("returns")
              .filter((r) => r.invoiceId === i.id)
              .reduce((s, r) => s + r.amount, 0);
            const net = Math.max(
              0,
              Math.round((i.amount - totalReturned) * 100) / 100,
            );
            save("invoices", {
              ...i,
              credit: totalReturned,
              refundDue: Math.max(0, i.paid - net),
              status:
                net === 0
                  ? "Credited"
                  : i.paid >= net
                    ? "Paid"
                    : i.paid
                      ? "Part paid"
                      : "Unpaid",
            });
            return r;
          }
          default:
            throw fail("Unknown action", 404);
        }
      });
      audit(u, req.params.action, result.id);
      res.json(result);
    } catch (e) {
      next(e);
    }
  });
  app.use("/api", (req, res) =>
    res.status(404).json({ error: "API route not found" }),
  );
  if (existsSync(path.join(root, "dist"))) {
    app.use(express.static(path.join(root, "dist")));
    app.get("/{*path}", (req, res) =>
      res.sendFile(path.join(root, "dist", "index.html")),
    );
  }
  app.use((e, req, res, next) => {
    if (!e.status) console.error(e);
    res
      .status(e.status || 500)
      .json({ error: e.status ? e.message : "Unexpected server error" });
  });
  return { app, db };
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { app } = createApp();
  const port = Number(process.env.PORT) || 4000;
  const host = process.env.HOST || "0.0.0.0";
  app.listen(port, host, () =>
    console.log(
      `Dyvora running at http://${host}:${port}`,
    ),
  );
}

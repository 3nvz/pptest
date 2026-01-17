const express = require("express");
const bodyParser = require("body-parser");

const app = express();
app.use(bodyParser.json());

// VULNERABLE deep merge (prototype pollution)
function deepMerge(target, source) {
  for (const key in source) {
    if (typeof source[key] === "object" && source[key] !== null) {
      if (!target[key]) {
        target[key] = {};
      }
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
}

app.post("/config", (req, res) => {
  const config = {};
  deepMerge(config, req.body);

  res.json({
    message: "Config updated",
    config,
    polluted: {}.isAdmin === true
  });
});

app.get("/admin", (req, res) => {
  if ({}.isAdmin) {
    res.send("ADMIN ACCESS GRANTED");
  } else {
    res.status(403).send("Access denied");
  }
});

app.listen(3000, () => {
  console.log("Vulnerable app running on http://localhost:3000");
});

const express = require("express");
const { deepMerge } = require("../lib/deepMerge");
const sinks = require("../lib/sinks");
const logic = require("../lib/logic");
const dispatch = require("../lib/dispatch");
const flags = require("../lib/flags");
const inter = require("../lib/interproc");

const router = express.Router();

router.post("/sinks/:t", async (req, res) => {
  const opts = {};
  deepMerge(opts, req.body);

  // GADGET #19
  if (req.params.t === "rce") return res.send(sinks.rce(opts));

  // GADGET #20
  if (req.params.t === "eval") return res.send(String(sinks.evalSink(opts)));

  // GADGET #21
  if (req.params.t === "fn") return res.send(String(sinks.functionCtor(opts)));

  // GADGET #22
  if (req.params.t === "read") return res.send(sinks.read(opts));

  // GADGET #23
  if (req.params.t === "write") return res.json({ ok: sinks.write(opts) });

  // GADGET #24
  if (req.params.t === "ssrf") return res.send(await sinks.ssrf(opts));

  // GADGET #25
  if (req.params.t === "tpl") return res.send(sinks.template(opts));

  // GADGET #26
  if (req.params.t === "yaml") return res.json(sinks.yamlLoad(opts));

  res.status(400).end();
});

router.post("/logic", (req, res) => {
  const opts = {};
  deepMerge(opts, req.body);

  // GADGET #27
  if (logic.auth(opts)) return res.json({ ok: true });

  // GADGET #28
  if (!logic.limits(opts)) return res.status(400).json({ ok: false });

  res.json({ ok: true });
});

router.get("/dispatch", (req, res) => {
  const opts = {};
  deepMerge(opts, req.query);

  // GADGET #29
  res.json({ result: dispatch.dispatch(opts) });
});

router.post("/method", (req, res) => {
  const opts = {};
  deepMerge(opts, req.body);

  // GADGET #30
  res.json({ method: dispatch.methodSelect(opts) });
});

router.get("/flags/:name", (req, res) => {
  const flagsObj = {};
  deepMerge(flagsObj, req.query);

  // GADGET #31
  const en = flags.enabled(flagsObj, req.params.name);

  // GADGET #32
  const v = flags.verbose(flagsObj);

  res.json({ en, v });
});

router.post("/inter", (req, res) => {
  const opts = {};
  deepMerge(opts, req.body);

  // GADGET #33
  if (inter.call(opts)) return res.json({ ok: true });

  res.json({ ok: false });
});

module.exports = router;


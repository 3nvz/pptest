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

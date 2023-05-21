const express = require("express");
const { spawn } = require("child_process");
const crypto = require("crypto");
const fs = require("fs/promises");
const app = express();
import axios from "axios";
require("dotenv").config();
const port = 3000;
app.get("/image", (req, res) => {
  const { name } = req.query; // Example: name=alpine:3.12
  if (!name) {
    return res.status(400).json({ error: "Missing image name" });
  }
  const uuid = crypto.randomUUID();
  res.json({ message: `Scanning image ${name}` });
  const command = spawn("grype", [
    name,
    "-o",
    "json",
    "--by-cve",
    "--file",
    `./scan-log/${uuid}.json`,
  ]);
  command.stdout.on("data", (data) => {
    console.log(`Received data: ${data}`);
  });
  command.on("close", async (code) => {
    console.log(`Child process exited with code ${code}`);
    // Process the output log
    try {
      // Create a folder if it doesn't exist
      await fs.mkdir("./scan-log", { recursive: true });
      const data = await fs.readFile(`./scan-log/${uuid}.json`, "utf8");
      const output = JSON.parse(data);
      const { matches } = output;
      const vulnerabilities = matches.map((match) => {
        const { vulnerability } = match;
        const { id, severity, description, cvss } = vulnerability;
        const cvssScore = cvss[cvss.length - 1]?.metrics.baseScore;
        return { cveId: id, severity, description, score: cvssScore };
      });
      // Send data to backend
      await axios.post(`${process.env.API_URL}/image`, {
        eventCode: "IMAGE_SCAN_COMPLETE",
        imageName: name,
        data: vulnerabilities,
      });
      // Delete the log file
      await fs.unlink(`./scan-log/${uuid}.json`);
    } catch (error) {
      console.log(error);
    }
  });
});

app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.listen(port, () => {
  console.log(`Image scanning service running on port ${port}`);
});

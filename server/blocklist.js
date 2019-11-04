const fs = require("fs");

const iplists = [
    "iblocklist_edu",
    "datacenters",
    "iblocklist_ads",
    "iblocklist_isp_sprint",
    "iblocklist_org_microsoft",
    "hphosts_ats",
    "coinbl_hosts",
    "coinbl_hosts_browser",
    "yoyo_adservers",
    "iblocklist_yoyo_adservers",
    "bitcoin_nodes_30d",
    "bitcoin_nodes_7d",
    "coinbl_ips",
    "bitcoin_nodes_1d",
    "bitcoin_nodes",
    "coinbl_hosts_optional",
    "iblocklist_isp_att",
    "iblocklist_isp_verizon",
    "iblocklist_isp_qwest",
    "iblocklist_isp_comcast",
    "iblocklist_isp_charter",
    "iblocklist_fornonlancomputers",
    "spamhaus_drop",
    "iblocklist_level2",
    "iblocklist_level3",
    "iblocklist_level1",
    "spamhaus_edrop",
    "pushing_inertia_blocklist",
    "iblocklist_rangetest",
    "alienvault_reputation",
    "ciarmy",
    "iblocklist_ciarmy_malicious",
    "iblocklist_spyware",
    "turris_greylist",
    "iblocklist_spider",
    "iblocklist_pedophiles",
    "nullsecure",
    "hphosts_psh",
    "hphosts_fsa",
    "bds_atif",
    "packetmail",
    "packetmail_ramnode",
    "hphosts_pha",
    "hphosts_wrz",
    "hphosts_mmt",
    "iblocklist_webexploit",
    "iblocklist_badpeers",
    "dronebl_auto_botnets",
    "packetmail_emerging_ips",
    "iblocklist_exclusions"
  ]

// Dependencies free HTTP(S) get promisified
function get(url) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith("https") ? require("https") : require("http");
    const request = lib.get(url, response => {
      if (response.statusCode < 200 || response.statusCode > 299) {
        reject(
          new Error("Failed to load page, status code: " + response.statusCode)
        );
      }

      const body = [];

      response.setEncoding("utf8");
      response.on("data", chunk => body.push(chunk));
      response.on("end", () => resolve(body.join("")));
    });

    request.on("error", err => reject(err));
  });
}

function loadBlockList(dumpFilePath) {
  return new Promise((resolve, reject) => {
    console.log("Going to try to load IP Blocklist");

    const dumpFileStats = fs.statSync(dumpFilePath);
    if (dumpFileStats && dumpFileStats.mtimeMs) {
      // 12 hours cache seems resonable
      if (Date.now() - dumpFileStats.mtimeMs < 12 * 3.6e6) {
        console.log("Loading IP Blocklist from cache");
        return resolve(fs.readFileSync(dumpFilePath, "utf8"));
      }
    }

    if (!Array.isArray(iplists)) return reject("Invalid iplists");

    const blockListBaseURL =
      "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/";
    const jobList = [];
    const blockList = new Set([]);

    // Make a queue for fetching those IPs
    iplists.forEach(list => {
      const ipsetURL = `${blockListBaseURL}${list}.ipset`;
      const netSetURL = `${blockListBaseURL}${list}.netset`;

      jobList.push(
        get(ipsetURL).catch(err => {
          //   console.error(err.message, ipsetURL);
          return "";
        })
      );

      jobList.push(
        get(netSetURL).catch(err => {
          //   console.error(err.message, netSetURL);
          return "";
        })
      );
    });

    // Run all the get requests and add the IPs to the blocklist set
    Promise.all(jobList)
      .then(data => {
        const lines = data.join("").split("\n");

        lines.forEach(line => {
          if (line && !line.startsWith("#")) blockList.add(line);
        });

        const blockListArray = Array.from(blockList);

        fs.writeFileSync(dumpFilePath, JSON.stringify(blockListArray));

        return resolve(blockListArray);
      })
      .catch(reject);
  });
}

module.exports = {
  loadBlockList
};

// loadBlockList(options.iplists)
//   .then(console.log)
//   .catch(console.error);

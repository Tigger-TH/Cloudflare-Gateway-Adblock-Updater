# Cloudflare Gateway Adblock Updater

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

This repository automates updating the Cloudflare Zero Trust Gateway  with the [Hagezi](https://github.com/hagezi/dns-blocklists) Multi Pro++, Dynamic DNS and DoH/VPN/TOR/Proxy Bypass filter lists using GitHub Actions. It fetches the lists daily at a given time, processes them by comparing the differences with existing lists, removing & updating the domains and splitting into 1,000-domain chunks, and creating new DNS blocking policies to enforce the updated filter lists.

Cloudflare's free plan supports up to 300 lists with no more than 1,000 domains in each list (300x1000 = 300K rules max), which is why the lists must be split.

# dns_blocklist
This repo generates a consolidated [AdGuard Home](https://adguard.com/en/adguard-home/overview.html)-compatible DNS blocklist.  Because I run multiple AdGuard Home instances, I wanted a single list for simplicity's sake across my home "enterprise."

## Sources

* OISD
* OISD NSFW (Small)
* Phishing URL Blocklist (PhishTank and OpenPhish lists)
* Ukrainian Security Filter
* HaGeZi's Threat Intelligence Feeds
* HaGeZi's Xiaomi Tracker Blocklist
* HaGeZi's Windows/Office Tracker Blocklist
* ShadowWhisperer's Dating List
* HaGeZi's Samsung Tracker Blocklist
* Dandelion Sprout's Game Console Adblock List
* Perflyst and Dandelion Sprout's Smart-TV Blocklist
* AdGuard Mobile Ads Filter

## Usage

Grab the link to the adguard-master.txt under `/output` and add it to your AdGuard Home under `DNS Blocklists`.
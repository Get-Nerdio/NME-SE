# Test-NmeDeploymentReadiness.ps1 — Open Issues / Future Fixes

1. ~~**Owner check is too narrow.**~~ **DONE.** The role check now accepts Contributor + User Access Administrator as an Owner-equivalent pass when Owner is not present (Owner is the union of those two, and the Terraform/pipeline install path documents the same acceptance).

2. ~~**Markdown table output is hard to read outside a markdown viewer.**~~ **DONE.** The copy/paste report now renders as aligned fixed-width columns (RESULT / CATEGORY / CHECK with wrapped `> ` detail lines) and a padded key/value config block — readable raw in any console, Slack, or email. No markdown table syntax remains; the JSON output is unchanged.

3. ~~**Prompts need an inline help option.**~~ **DONE.** `Read-YesNo` now takes an optional `-Help` string and accepts `?` to show it and re-prompt; a new `Read-Choice` helper renders numbered options with an always-present `?`; a `Write-HelpText` helper word-wraps help blocks. Private-endpoint, existing-vs-new-VNet, and new-VNet-DNS-mode prompts carry sourced `?` explanations.

   3a. ~~**Complex prompts → numbered options.**~~ **DONE.** The three complex/ambiguous prompts (private endpoints; existing vs new VNet; Azure vs custom DNS) are now 1/2/? numbered `Read-Choice` prompts; simple confirmations stay y/n (the existing-RG and custom-tags prompts gained `-Help` explanations).

4. ~~**Private endpoint path should distinguish new vs. existing Private DNS zones.**~~ **DONE.** A new numbered prompt asks existing-vs-new Private DNS zones (Azure-DNS path only). Existing: prompt for the zones' subscription/RG (context-switching to that subscription for the read-only lookup) and report which required zones are missing from that RG; also report linkage on the existing-VNet path. New: test-create the required zones in the throwaway test RG (tracked + cleaned up, blocking policy named on failure).

5. **Existing VNet private endpoint testing should report only what's missing.** When testing private endpoints against an existing VNet, deploy test private endpoints and confirm all required DNS zones are linked to that VNet — report only the zones that are missing or not linked, not the full list.

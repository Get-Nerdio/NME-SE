# Test-NmeDeploymentReadiness.ps1 — Open Issues / Future Fixes

1. ~~**Owner check is too narrow.**~~ **DONE.** The role check now accepts Contributor + User Access Administrator as an Owner-equivalent pass when Owner is not present (Owner is the union of those two, and the Terraform/pipeline install path documents the same acceptance).

2. **Markdown table output is hard to read outside a markdown viewer.** The report is rendered as a markdown table but is usually read in a plain console or pasted into Slack/email. Replace with (or add) a plain-text/columnar or indented list format that's readable without markdown rendering.

3. ~~**Prompts need an inline help option.**~~ **DONE.** `Read-YesNo` now takes an optional `-Help` string and accepts `?` to show it and re-prompt; a new `Read-Choice` helper renders numbered options with an always-present `?`; a `Write-HelpText` helper word-wraps help blocks. Private-endpoint, existing-vs-new-VNet, and new-VNet-DNS-mode prompts carry sourced `?` explanations.

   3a. ~~**Complex prompts → numbered options.**~~ **DONE.** The three complex/ambiguous prompts (private endpoints; existing vs new VNet; Azure vs custom DNS) are now 1/2/? numbered `Read-Choice` prompts; simple confirmations stay y/n (the existing-RG and custom-tags prompts gained `-Help` explanations).

4. **Private endpoint path should distinguish new vs. existing Private DNS zones.** Ask up front whether the customer will use existing Private DNS zones or have the script create new ones:
   - If **existing**: prompt for the subscription/resource group containing the zones, then check and report which required private DNS zones are missing from that resource group.
   - If **new**: test creating the required Private DNS zones in the test resource group.

5. **Existing VNet private endpoint testing should report only what's missing.** When testing private endpoints against an existing VNet, deploy test private endpoints and confirm all required DNS zones are linked to that VNet — report only the zones that are missing or not linked, not the full list.

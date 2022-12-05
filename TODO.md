# TODO

## General
1. Install the app - Splunk Essentials for Cloud and Enterprise

2. Create an App for Cyber, there we will put our custom:
    - eventtype
    - macros
    - field aliases
    - investigation dashboards
    - statistical dashboards

## Data Models
1. Add the field process_name to Endpoint.Registry

2. Adding a user to the Domain Admins group doesn't arrive to Change.Account_Updated, this because action is success (and updated or modified as the constraints dictates)

3. Use Splunk Security Essentials -> Security Operations -> CIM Compliance Check, to get statistics about fields population per product

## Macros
1. Create a macro for each data vendor (like master filters), optimize it by specifying the index, source and sourcetype

2. Create and maintain a single macro for each rule for exceptions, the name convention will be `<rule_name>-exceptions` (no spaces allowed)
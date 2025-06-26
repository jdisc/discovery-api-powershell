# discovery-api-powershell
Powershell scripts and modules for JDisc Discovery API

# Setup
We use a module for accessing the JDisc JQuery API endpoint

`Install-Module -Name PSGraphQL -Repository PSGallery -Scope CurrentUser`

Attention JDisc module does not yet work because it needs to be copied to a module location

# Run

Pass the username and password and optionally a remote url
`discover-local.ps1 -url http://server:port/graphql -user %USERNAME% -password 'secret'`

Pass the password using the -password parameter from the command line. If omitted, you will be interactively prompted for the password
`run-graphql-query.ps1 -apiUrl http://server:port/graphql -username <user> -graphQLQueryFileName <QueryFileName> -graphQLResponseFileName <QueryResponseFileName>` 

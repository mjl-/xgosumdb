xgosumdb is a basic Go sumdb server that serves requests from its database,
and reads unknown modules from a Go module proxy adding them to its database
for future requests.

Starting for the first time:

	$ xgosumdb -init localhost

A new signer key is generated, a database with empty tree initialized, and a
new go sumdb server started on http://localhost:3080. The GOSUMDB environment
variable value to use in "go get" and "go install" invocations is printed.

After the initial run, leave out "-init localhost".

Example with other flags:

	$ xgosumdb -loglevel debug -proxy https://proxy.golang.org

See the help output for using a different database path, listener address, etc.

The suggested GOSUMDB variable would look like this:

	GOSUMDB='localhost+b24f3ed0+AZwJvAwnQwYfoytqj3/oISb+LdzvA4aE3C4qc/i88Yar http://localhost:3080'

While you're testing with a localhost sumdb, you may want to clean the cached
sumdb state in between resetting key and/or database. Otherwise you will get
errors about a misbehaving transparency log:

	rm -r $HOME/go/pkg/mod/cache/download/sumdb/localhost $HOME/go/pkg/sumdb/localhost

Compile:

	GOBIN=$PWD go install github.com/mjl-/xgosumdb@latest

Download binary:

	https://beta.gobuilds.org/github.com/mjl-/xgosumdb@latest

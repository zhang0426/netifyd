EXTRA_DIST = app-content-match.csv app-host-match.csv app-host-match.sed
			clearos exec-pre.sh netifyd.conf netifyd.service netifyd.tmpf

all: app-content-match.csv app-host-match.csv

app-content-match.csv: ../util/nd-app-match-export
	../util/nd-app-content-match-export -C app-content-match.csv

app-host-match.csv: ../util/nd-app-match-export
	../util/nd-app-content-match-export -H app-host-match.csv
	sed -i -f app-host-match.sed app-host-match.csv

